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

static pcap_t *
newPcapDesc (char *interface) {
    int ret;
    pcap_t *pcapDesc;
    pcap_if_t *alldevs, *devptr;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    if (getPropertiesPcapOfflineInput ()) {
        pcapDesc = pcap_open_offline (getPropertiesPcapOfflineInput(), errBuf);
        if (pcapDesc) {
            LOGI ("Use pcap offline input: %s.\n", getPropertiesPcapOfflineInput ());
            return pcapDesc;
        }

        LOGE ("Open pcap offline input error %s, will use default network device.\n", errBuf);
    }

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

pcap_t *
getNetDev (void) {
    return pcapDescInstance;
}

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
updateFilter (char *filter) {
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

/* Init net device */
int
initNetDev (void) {
    /* Create pcap descriptor instance */
    pcapDescInstance = newPcapDesc (getPropertiesMirrorInterface ());
    if (pcapDescInstance == NULL) {
        LOGE ("Create pcap descriptor instance error.\n");
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
    pcap_close (pcapDescInstance);
    pcapDescInstance = NULL;
    datalinkType = -1;
}
