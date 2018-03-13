import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class MainTest
{
    public static void main(String[] args)
    {
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();

        int r = Pcap.findAllDevs(devices, errbuf);
        if(r == Pcap.NOT_OK || devices.isEmpty())
        {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            return;
        }
        System.out.println("Network devices found:");
        int i = 0;
        for(PcapIf device : devices)
        {
            String desc = device.getDescription() != null ? device.getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), desc);
        }
        PcapIf device = devices.get(4);
        System.out.printf("\nChoosing '%s' on your behalf:\n", device.getDescription() != null ? device.getDescription() : device.getName());
        int snaplen = 64 * 1024;
        int flags = Pcap.MODE_PROMISCUOUS;
        int timeout = 10 * 1000;
        Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if (pcap == null)
        {
            System.err.printf("Error while opening device for capture: " + errbuf.toString());
            return;
        }
        PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket pcapPacket, String s) {
                System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                        new Date(pcapPacket.getCaptureHeader().timestampInMillis()),
                        pcapPacket.getCaptureHeader().caplen(),
                        pcapPacket.getCaptureHeader().wirelen(),
                        s);
            }
        };
        pcap.loop(10, handler, "jNetPcap rocks!");
        pcap.close();
    }
}
