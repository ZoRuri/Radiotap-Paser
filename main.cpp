#include <QCoreApplication>
#include <QDebug>
#include <pcap.h>
#include <ieee80211_radiotap.h>

int BitShift(int num);
int NaturalBoundary(int padding, int byte);

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    const char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    dev = "wlan4";
    pcap_t *handle;
    struct pcap_pkthdr *pkthdr;
    const u_char *data;

    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

    while(true)
    {
        pcap_next_ex(handle, &pkthdr, &data);

//        int padding = 0;
        int present = 4;    // Present Flags

        int padding = sizeof(struct ieee80211_radiotap_header);

        struct ieee80211_radiotap_header *rdh = (struct ieee80211_radiotap_header *)data;

        while (*((u_int32_t*)(data + present)) & BitShift(IEEE80211_RADIOTAP_EXT))
        {
            present += 4;
            padding += 4;
        }

        Radiotap:   // Because of EXT

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE)) { // 4Bytes padding for 0 index
            padding = NaturalBoundary(padding, 4);
            padding += 4;
        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_TSFT)) {  //  MAC Timestamp 8Bytes
            padding = NaturalBoundary(padding, 8);
            qDebug() << "TimeStamp:"<< *((u_int64_t*)(data + padding));
            padding += 8;
        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_FLAGS)) { // Flags 1Byte
            padding = NaturalBoundary(padding, 1);
            qDebug() << "Flag:" << *((u_int8_t*)(data + padding));
            padding += 1;
        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_RATE)) {  // Rate 1Byte 500kb/s
            padding = NaturalBoundary(padding, 1);
            qDebug() << "Rate:" << *((u_int8_t*)(data + padding)) /2 << "MB/s";
            padding += 1;
        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_CHANNEL)) {   // Frequency 2byte MHz
            padding = NaturalBoundary(padding, 2);
            qDebug() << "Frequency:" << *((u_int16_t*)(data + padding)) * 0.001 << "GHz";
            padding += 2;
            padding = NaturalBoundary(padding, 2);
            qDebug() << "Channel bitmap:" << *((u_int16_t*)(data + padding));
            padding += 2;
        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_FHSS)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_DBM_ANTSIGNAL)) { // Singal dBm
            padding = NaturalBoundary(padding, 1);
            qDebug() << "Signal:" << *((int8_t*)(data + padding)) << "dBm";
            padding += 1;
        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_DBM_ANTNOISE)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_LOCK_QUALITY)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_TX_ATTENUATION)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_DB_TX_ATTENUATION)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_DBM_TX_POWER)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_ANTENNA)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_DB_ANTSIGNAL)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_DB_ANTNOISE)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_RX_FLAGS)) {
            padding = NaturalBoundary(padding, 2);
            qDebug() << "RX Flags:" << *((u_int16_t*)(data + padding));
            padding += 2;
        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_TX_FLAGS)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_RTS_RETRIES)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_DATA_RETRIES)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_MCS)) { // 19

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_AMPDU_STATUS)) {

        }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_VHT)) {

        }

//            if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE)) { // 4 padding for 0 index
//                padding += 4;
//            }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_VENDOR_NAMESPACE)) {

        }

//            if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_EXT)) {  // Extension Present Flags
//                rdh->it_present = *((u_int32_t*)(data + sizeof(struct ieee80211_radiotap_header) + 4));
//            }

        if (rdh->it_present & BitShift(IEEE80211_RADIOTAP_EXT)) {  // Extension Present Flags
            rdh->it_present = *((u_int32_t*)(data + (sizeof(struct ieee80211_radiotap_header))));
            goto Radiotap;  //  goto Line 39
        }

    }

    return a.exec();
}

int BitShift(int num) {
    return 1 << num;
}

int NaturalBoundary(int padding, int byte) {    // Radiotap need natural boundary for alignment
    if(!(padding % byte))   return padding;
    else return padding += padding % byte;

}