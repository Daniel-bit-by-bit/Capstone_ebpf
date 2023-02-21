package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"C"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)



func main() {
	log.Printf("Attaching eBPF monitoring programs to cgroup %s\n", TARGET_CGROUP_V2_PATH)

	// ------------------------------------------------------------
	// -- The real program initialization will be somewhere here --
	const (
		TARGET_CGROUP_V2_PATH = "/sys/fs/cgroup/unified/yadutaf" // <--- Change as needed for your system/use-case
		EBPF_PROG_ELF         = "./bpf-accounting.bpf.o"
	)
	
	type BPFCgroupNetworkDirection struct {
		Name       string
		AttachType ebpf.AttachType
	}
	
	var BPFCgroupNetworkDirections = []BPFCgroupNetworkDirection{
		{
			Name:       "ingress",
			AttachType: ebpf.AttachCGroupInetIngress,
		}, low-overhead-cgroup-network-accounting-with-ebpf,
		{
			Name:       "egress",
			AttachType: ebpf.AttachCGroupInetEgress,
		},
	}
	// Increase max locked memory (for eBPF maps)
	// For a real program, make sure to adjust to actual needs
	unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	})low-overhead-cgroup-network-accounting-with-ebpf
	
	collec, err := ebpf.LoadCollection(EBPF_PROG_ELF)
	if err != nil {
		log.Fatal(err)
	}

	// Get a handle on the statistics map
	cgroup_counters_map := collec.Maps["cgroup_counters_map"]

	type BpfCgroupStorageKey struct {
		CgroupInodeId uint64
		AttachType    ebpf.AttachType
		_             uint32
	}
	//go program only needs a definition of the member type. Since the program uses a per-CPU data structure, this needs to be a slice
	type PerCPUCounters []uint64

	//since we are interested in the total number of transmitted bytes regardless of the CPU cores, here is a tiny helper
	func sumPerCpuCounters(perCpuCounters PerCPUCounters) uint64 {
		sum := uint64(0)
		for _, counter := range perCpuCounters {
			sum += counter
		}
		return sum
	}
	// Get cgroup folder inode number to use as a key in the per-cgroup map
	cgroupFileinfo, err := os.Stat(TARGET_CGROUP_V2_PATH)
	if err != nil {
		log.Fatal(err)
	}
	cgroupStat, ok := cgroupFileinfo.Sys().(*syscall.Stat_t)
	if !ok {
		log.Fatal("Not a syscall.Stat_t")
	}
	cgroupInodeId := cgroupStat.Ino

	inline int handle_skb(struct __sk_buff *skb)
	{
    	__u16 bytes = 0;

    // Extract packet size from IPv4 / IPv6 header
    switch (skb->family)
    {
    case AF_INET:
        {
            struct iphdr iph;
            bpf_skb_load_bytes(skb, 0, &iph, sizeof(struct iphdr));
            bytes = ntohs(iph.tot_len);
            break;
        }
    case AF_INET6:
        {
            struct ip6_hdr ip6h;
            bpf_skb_load_bytes(skb, 0, &ip6h, sizeof(struct ip6_hdr));
            bytes = ntohs(ip6h.ip6_plen);
            break;
        }
    default:
        // This should never be the case as this eBPF hook is called in
        // netfilter context and thus not for AF_PACKET, AF_UNIX nor AF_NETLINK
        // for instance.
        return true;
    }
    // Update counters in the per-cgroup map
    __u64 *bytes_counter = bpf_get_local_storage(&cgroup_counters_map, 0);
    __sync_fetch_and_add(bytes_counter, bytes);

    // Let the packet pass
    return true;
}

// Ingress hook - handle incoming packets
SEC("cgroup_skb/ingress") int ingress(struct __sk_buff *skb)
{
    return handle_skb(skb);
}

// Egress hook - handle outgoing packets
SEC("cgroup_skb/egress") int egress(struct __sk_buff *skb)
{
    return handle_skb(skb);
}

// Attach program to monitored cgroup
for _, direction := range BPFCgroupNetworkDirections {
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    TARGET_CGROUP_V2_PATH,
		Attach:  direction.AttachType,
		Program: collec.Programs[direction.Name],
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()
}

	// ------------------------------------------------------------

	// Wait until signaled
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT)
	signal.Notify(c, syscall.SIGTERM)

	// Periodically check counters
	ticker := time.NewTicker(1 * time.Second)

out:
	for {
		select {
		case <-ticker.C:
			log.Println("-------------------------------------------------------------")

			// ------------------------------------------
			// -- And here will be the counters report --
			for _, direction := range BPFCgroupNetworkDirections {
				var perCPUCounters PerCPUCounters

				mapKey := BpfCgroupStorageKey{
					CgroupInodeId: cgroupInodeId,
					AttachType:    direction.AttachType,
				}

				if err := cgroup_counters_map.Lookup(mapKey, &perCPUCounters); err != nil {
					log.Printf("%s: error reading map (%v)", direction.Name, err)
				} else {
					log.Printf("%s: %d\n", direction.Name, sumPerCpuCounters(perCPUCounters))
				}
			}
			// ------------------------------------------

		case <-c:
			log.Println("Exiting...")
			break out
		}
	}
}