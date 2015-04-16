#include <net/if.h>
#include <pcap.h>
#include "log.h"
#include "properties.h"
#include "netdev.h"

/* Pcap settings */
#define PCAP_MAX_CAPTURE_LENGTH 65535
#define PCAP_CAPTURE_TIMEOUT 500
#define PCAP_CAPTURE_IN_PROMISC 1
#define PCAP_CAPTURE_BUFFER_SIZE (32 << 20)

/* Pcap descriptor instance */
static pcap_t *pcapDescInstance = NULL;
/* Datalink type */
static int datalinkType = -1;

/* Pcap offline file load count */
static u_int pcapOfflineLoadCount = 0;

static pcap_t *
newPcapOfflineDesc (char *pcapFile) {
    pcap_t *pcapDesc;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    pcapDesc = pcap_open_offline (pcapFile, errBuf);
    if (pcapDesc == NULL)
        LOGE ("%s\n", errBuf);

    return pcapDesc;
}

static pcap_t *
newPcapInterfaceDesc (char *interface) {
    int ret;
    pcap_t *pcapDesc;
    pcap_if_t *alldevs, *devptr;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    /* Check interface exists */
    ret = pcap_findalldevs (&alldevs, errBuf);
    if (ret < 0) {
        LOGE ("No network devices found: %s.\n", errBuf);
        return NULL;
    }

    for (devptr = alldevs; devptr != NULL; devptr = devptr->next) {
        if (strEqual (devptr->name, interface))
            break;
    }
    if (devptr == NULL) {
        LOGE ("Interface \"%s\" not found.\nInterfaces possible: ", interface);
        for (devptr = alldevs; devptr != NULL; devptr = devptr->next) {
            if (devptr->next)
                LOGE ("\"%s\", ", devptr->name);
            else
                LOGE ("\"%s\"\n", devptr->name);
        }
        return NULL;
    }

    /* Create pcap descriptor */
    pcapDesc = pcap_create (interface, errBuf);
    if (pcapDesc == NULL) {
        LOGE ("Create pcap descriptor error: %s.\n", errBuf);
        return NULL;
    }

    /* Set pcap max capture length */
    ret = pcap_set_snaplen (pcapDesc, PCAP_MAX_CAPTURE_LENGTH);
    if (ret < 0) {
        LOGE ("Set pcap snaplen error\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    /* Set pcap promisc mode */
    ret = pcap_set_promisc (pcapDesc, PCAP_CAPTURE_IN_PROMISC);
    if (ret < 0) {
        LOGE ("Set pcap promisc mode error.\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    /* Set pcap timeout */
    ret = pcap_set_timeout (pcapDesc, PCAP_CAPTURE_TIMEOUT);
    if (ret < 0) {
        LOGE ("Set capture timeout error.\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    /* Set pcap buffer size */
    ret = pcap_set_buffer_size (pcapDesc, PCAP_CAPTURE_BUFFER_SIZE);
    if (ret < 0) {
        LOGE ("Set pcap capture buffer size error.\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    /* Activate pcap descriptor */
    ret = pcap_activate (pcapDesc);
    if (ret < 0) {
        LOGE ("Activate pcap descriptor error.\n");
        pcap_close (pcapDesc);
        return NULL;
    }

    return pcapDesc;
}

static int
initPcapDesc (void) {
    if (getPropertiesPcapFile ()) {
        pcapDescInstance = newPcapOfflineDesc (getPropertiesPcapFile ());
        if (pcapDescInstance) {
            LOGI ("Use pcap file: %s as input.\n", getPropertiesPcapFile ());
            pcapOfflineLoadCount++;
            return 0;
        }

        LOGE ("Open pcap offline file error, will use default network interface.\n");
    }

    if (getPropertiesInterface ()) {
        pcapDescInstance = newPcapInterfaceDesc (getPropertiesInterface ());
        if (pcapDescInstance == NULL) {
            LOGE ("Open interface: %s error.\n", getPropertiesInterface ());
            return -1;
        } else {
            LOGI ("Use interface: %s as input.\n", getPropertiesInterface ());
            return 0;
        }
    }

    LOGE ("Input \"Input.Interface\" and \"Input.PcapOffline\" are all empty, at least set one.");
    return -1;
}

/* Get net dev descriptor */
pcap_t *
getNetDevPcapDesc (void) {
    return pcapDescInstance;
}

/* Get net dev data link type */
int
getNetDevDatalinkType (void) {
    return datalinkType;
}

/* Get net device packets statistic info */
int
getNetDevPakcetsStatistic (u_int *pktsRecv, u_int *pktsDrop) {
    int ret;
    struct pcap_stat ps;

    ret = pcap_stats (pcapDescInstance, &ps);
    if (ret < 0)
        return -1;

    *pktsRecv = ps.ps_recv;
    *pktsDrop = ps.ps_drop;
    return 0;
}

/* Update filter of net device */
int
updateNetDevFilter (char *filter) {
    int ret;
    struct bpf_program pcapFilter;

    ret = pcap_compile (pcapDescInstance, &pcapFilter, filter, 1, 0);
    if (ret < 0) {
        pcap_freecode (&pcapFilter);
        return -1;
    }

    ret = pcap_setfilter (pcapDescInstance, &pcapFilter);
    pcap_freecode (&pcapFilter);
    return ret;
}

/* Reload net device */
int
reloadNetDev (void) {
    if (pcapDescInstance) {
        pcap_close (pcapDescInstance);
        pcapDescInstance = NULL;
    }

    if (getPropertiesPcapFile () && (getPropertiesLoopCount () == 0 ||
                                     pcapOfflineLoadCount < getPropertiesLoopCount ())) {
        pcapDescInstance = newPcapOfflineDesc (getPropertiesPcapFile ());
        if (pcapDescInstance == NULL) {
            LOGE ("Reload pcap offline file error.\n");
            return -1;
        }

        pcapOfflineLoadCount++;
        return 0;
    }

    if (getPropertiesInterface ()) {
        pcapDescInstance = newPcapInterfaceDesc (getPropertiesInterface ());
        if (pcapDescInstance == NULL) {
            LOGE ("Reload interface: %s error.\n", getPropertiesInterface ());
            return -1;
        }

        if (pcapOfflineLoadCount >= getPropertiesLoopCount ())
            return 1;
        else
            return 0;
    }

    return -1;
}

/* Init net device */
int
initNetDev (void) {
    int ret;

    /* Create pcap descriptor instance */
    ret = initPcapDesc ();
    if (ret < 0) {
        LOGE ("Init pcap descriptor instance error.\n");
        return -1;
    }

    /* Get datalink type */
    datalinkType = pcap_datalink (pcapDescInstance);
    if (datalinkType < 0) {
        LOGE ("Get datalink type error.\n");
        pcap_close (pcapDescInstance);
        pcapDescInstance = NULL;
        return -1;
    }

    return 0;
}

/* Destroy net device */
void
destroyNetDev (void) {
    if (pcapDescInstance) {
        pcap_close (pcapDescInstance);
        pcapDescInstance = NULL;
    }
}
