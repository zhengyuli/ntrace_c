#include <net/if.h>
#include <pcap.h>
#include "log.h"
#include "properties.h"
#include "netdev.h"

/* Pcap settings */
#define PCAP_MAX_CAPTURE_LENGTH 65535
#define PCAP_CAPTURE_TIMEOUT 500
#define PCAP_CAPTURE_IN_PROMISC 1
#define PCAP_CAPTURE_BUFFER_SIZE (16 << 20)

static pcap_t *pcapDescInstance = NULL;
static int linkType = -1;

/*
 * @brief Create a new pcap descriptor
 *
 * @param interface net interface bind to pcap descriptor
 *
 * @return pcap descriptor if success else NULL
 */
static pcap_t *
newPcapDev (const char *interface) {
    int ret;
    pcap_t *pcapDev;
    pcap_if_t *alldevs, *devptr;
    char errBuf [PCAP_ERRBUF_SIZE] = {0};

    /* Check interface exists */
    ret = pcap_findalldevs (&alldevs, errBuf);
    if (ret < 0) {
        LOGE ("No network devices found.\n");
        return NULL;
    }

    for (devptr = alldevs; devptr != NULL; devptr = devptr->next) {
        if (strEqual (devptr->name, interface))
            break;
    }
    if (devptr == NULL)
        return NULL;

    /* Create pcap descriptor */
    pcapDev = pcap_create (interface, errBuf);
    if (pcapDev == NULL) {
        LOGE ("Create pcap device error: %s.\n", errBuf);
        return NULL;
    }

    /* Set pcap max capture length */
    ret = pcap_set_snaplen (pcapDev, PCAP_MAX_CAPTURE_LENGTH);
    if (ret < 0) {
        LOGE ("Set pcap snaplen error\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap timeout */
    ret = pcap_set_timeout (pcapDev, PCAP_CAPTURE_TIMEOUT);
    if (ret < 0) {
        LOGE ("Set capture timeout error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap buffer size */
    ret = pcap_set_buffer_size (pcapDev, PCAP_CAPTURE_BUFFER_SIZE);
    if (ret < 0) {
        LOGE ("Set pcap capture buffer size error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Set pcap promisc mode */
    ret = pcap_set_promisc (pcapDev, PCAP_CAPTURE_IN_PROMISC);
    if (ret < 0) {
        LOGE ("Set pcap promisc mode error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    /* Activate pcap device */
    ret = pcap_activate (pcapDev);
    if (ret < 0) {
        LOGE ("Activate pcap device error.\n");
        pcap_close (pcapDev);
        return NULL;
    }

    return pcapDev;
}

pcap_t *
getNetDev (void) {
    return pcapDescInstance;
}

int
getNetDevLinkType (void) {
    return linkType;
}

int
updateFilter (const char *filter) {
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
    pcapDescInstance = newPcapDev (getPropertiesMirrorInterface ());
    if (pcapDescInstance == NULL) {
        LOGE ("Create pcap descriptor for %s error.\n", getPropertiesMirrorInterface ());
        return -1;
    }

    /* Get link type */
    linkType = pcap_datalink (pcapDescInstance);
    if (linkType < 0) {
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
    linkType = -1;
}
