import flags.FlagParser;
import flags.InvalidCommandException;
import flags.types.AbstractFlag;
import flags.types.FlagType;

import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.*;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class CommandExecutor
{
    private volatile static FlagParser parser;
    private volatile static CommandExecutor instance;
    private volatile boolean ASCII = false;
    private volatile int buffer_size;
    private volatile int count = 0;
    private volatile long file_size = 0;
    private volatile String filter = "";
    private volatile int rotation = 0;
    private volatile boolean print = false;
    private volatile boolean unbuffered = false;
    private volatile String text_pattern = "";
    private volatile String src_string = "";
    private volatile String dst_string = "";
    private volatile String port_string = "";
    private volatile String proto_string = "";
    private volatile String dir_string = "";
    private volatile String ifile = "";
    private volatile String ofile = "";
    private volatile int mode = 0;
    private volatile int cap_iface_int = 0;
    private volatile String iface_name = "";


    private CommandExecutor(){};

    public static CommandExecutor getInstance()
    {
        if(instance == null)
        {
            synchronized(CommandExecutor.class)
            {
                if(instance == null)
                    instance = new CommandExecutor();
            }
        }
        return instance;
    }

    public void setParser(FlagParser parser)
    {
        if(parser != null && this.parser == null)
            this.parser = parser;
    }

    public void execute(String[] tokens) throws InvalidCommandException {
        List<AbstractFlag> flags = parser.parseFlags(tokens);
        if(!flags.isEmpty())
        {
            for(AbstractFlag f : flags)
            {
                FlagType type = f.getType();
                if(type == FlagType.ASCII)
                    ASCII = true;
                else if(type == FlagType.BUFFER_SIZE)
                    System.out.println("*** Command -B/--buffer_size not currently supported ***");
                else if(type == FlagType.COUNT)
                    setCount(f);
                else if(type == FlagType.FILE_SIZE)
                    setFileSize(f);
                else if(type == FlagType.DEVICES)
                    printDevices();
                else if(type == FlagType.FILE)
                    getFilter(f);
                else if(type == FlagType.ROTATE)
                    setRotation(f);
                else if(type == FlagType.HELP)
                    printHelp();
                else if(type == FlagType.VERSION)
                    printVersion();
                else if(type == FlagType.INTERFACE)
                    setCaptureInterface(f);
                else if(type == FlagType.MON_MODE)
                    System.err.println("*** Command -M/--monitor_mode not currently supported ***");
                else if(type == FlagType.MODE)
                    setDeviceMode(f);
                else if(type == FlagType.PRINT)
                    print = true;
                else if(type == FlagType.DIRECTION)
                    setDirection(f);
                else if(type == FlagType.IN_FILE)
                    setInput(f);
                else if(type == FlagType.OUT_FILE)
                    setOutput(f);
                else if(type == FlagType.PORT)
                    setListeningPorts(f);
                else if(type == FlagType.PROTOCOL)
                    setProtocol(f);
                else if(type == FlagType.SOURCE)
                    setSource(f);
                else if(type == FlagType.DESTINATION)
                    setDestination(f);
                else if(type == FlagType.UNBUFFERED)
                    unbuffered = true;
                else if(type == FlagType.PATTERN)
                    setTextPattern(f);
            }
        }
        else
        {
            System.out.println("*** Beginning default capture ***");
            print = true;
        }
        capture();
    }

    private void setTextPattern(AbstractFlag f) throws InvalidCommandException {

        if(f.getParameters().length >= 1)
            text_pattern = f.getParameters()[0];
        else
        {
            System.err.println("Invalid parameter for flag -pat/--pattern");
            return;
        }
        try
        {
            Pattern.compile(text_pattern);
        }
        catch(PatternSyntaxException pse)
        {
            throw new InvalidCommandException("Invalid expression syntax for flag -pat/--pattern");
        }
    }

    private void setDestination(AbstractFlag f)
    {
        String[] params = f.getParameters();
        if(params.length == 1)
        {
            dst_string = "dst " + params[0];
            System.out.println("Set destination filter to: " + dst_string);
        }
        else
        {
            if(src_string.equals("") && port_string.equals("") && proto_string.equals("") && dir_string.equals(""))
            {
                dst_string = "dst ";
                for(int i = 0; i < params.length; i++)
                {
                    if(i != params.length - 1)
                        dst_string += params[i] + " || ";
                    else
                        dst_string += params[i];
                }
                System.out.println("Set destination filter to: " + dst_string);
                return;
            }
            else
            {
                dst_string = "(dst";
                for (int i = 0; i < params.length; i++)
                {
                    if (i != params.length - 1)
                        dst_string += params[i] + " || ";
                    else
                        dst_string += params[i] + ")";
                }
                System.out.println("Set destination filter to: " + dst_string);
            }
        }
    }

    private void setSource(AbstractFlag f)
    {
        String[] params = f.getParameters();
        if(params.length == 1)
            src_string = "src " + params[0];
        else
        {
            if(dst_string.equals("") && port_string.equals("") && proto_string.equals("") && dir_string.equals(""))
            {
                src_string = "src ";
                for(int i = 0; i < params.length; i++)
                {
                    if(i != params.length - 1)
                        src_string += params[i] + " || ";
                    else
                        src_string += params[i];
                }
                System.out.println("Set source filter to: " + src_string);
                return;
            }
            src_string = "(src ";
            for(int i = 0; i < params.length; i++)
            {
                if(i != params.length - 1)
                    src_string += params[i] + " || ";
                else
                    src_string += params[i] + ")";
            }
            System.out.println("Set src filter to: " + src_string);
        }
    }

    private void setProtocol(AbstractFlag f)
    {
        String[] params = f.getParameters();
        if(params.length == 1)
            proto_string = params[0];
        else
        {
            if(src_string.equals("") && dst_string.equals("") && port_string.equals("") && dir_string.equals(""))
            {
                for(int i = 0; i < params.length; i++)
                {
                    if(i != params.length - 1)
                        src_string += params[i] + " || ";
                    else
                        src_string += params[i];
                }
                System.out.println("Set protocol filter to: " + proto_string);
                return;
            }
            proto_string = "(";
            for(int i = 0; i < params.length; i++)
            {
                if(i != params.length - 1)
                    proto_string += params[i] + " || ";
                else
                    proto_string += params[i] + ")";
            }
            System.out.println("Set protocol filter to: " + proto_string);
        }
    }

    private void setListeningPorts(AbstractFlag f)
    {
        String[] params = f.getParameters();
        if(params.length == 1)
            port_string = "port " + params[0];
        else
        {
            if(src_string.equals("") && dst_string.equals("") && proto_string.equals("") && dir_string.equals(""))
            {
                port_string = "port ";
                for(int i = 0; i < params.length; i++)
                {
                    if(i != params.length - 1)
                        port_string += params[i] + " || ";
                    else
                        port_string += params[i];
                }
                System.out.println("Set port filter to: " + port_string);
                return;
            }
            port_string = "(port ";
            for(int i = 0; i < params.length; i++)
            {
                if(i != params.length - 1)
                    port_string += params[i] + " || ";
                else
                    port_string += params[i] + ")";
            }
            System.out.println("Set port filter to: " + port_string);
        }
    }

    private void setOutput(AbstractFlag f) throws InvalidCommandException {
        String fname = f.getParameters().length >= 1 ? f.getParameters()[0] : "";
        File temp = new File(fname);
        if(temp.exists())
            throw new InvalidCommandException("File " + fname + " already exists.");
        ofile = fname;
        System.out.println("Set output file to: " + ofile);
    }

    private void setInput(AbstractFlag f) throws InvalidCommandException {
        String fname = f.getParameters().length >= 1 ? f.getParameters()[0] : "";
        File temp = new File(fname);
        if(!temp.exists())
            throw new InvalidCommandException("File " + fname + " does not exist");
        ifile = fname;
        System.out.println("Set input file to: " + ifile);
    }

    private void setDirection(AbstractFlag f)
    {
        dir_string = f.getParameters().length >= 1 ? f.getParameters()[0] : "";
        System.out.println("Set direction filter to: " + dir_string);
    }

    private void setDeviceMode(AbstractFlag f)
    {
        String mode = f.getParameters().length >= 1 ? f.getParameters()[0] : "";
        if(mode.equals("PROMISCUOUS"))
            this.mode = Pcap.MODE_PROMISCUOUS;
        else if(mode.equals("PASSIVE"))
            this.mode = Pcap.MODE_NON_PROMISCUOUS;
        System.out.println("Set device mode to: " + (mode.equals("PROMISCUOUS") ? "PROMISCUOUS" : "PASSIVE"));
    }

    private void setCaptureInterface(AbstractFlag f)
    {
        String iface = f.getParameters().length >= 1 ? f.getParameters()[0] : "";
        try
        {
            cap_iface_int = Integer.parseInt(iface);
        }
        catch(NumberFormatException nfe)
        {
            iface_name = iface;
        }
        System.out.println("Set capture interface to: Interface " + iface);
    }

    private void printVersion()
    {
        try
        {
            Scanner fin = new Scanner("VERSION.txt");
            while(fin.hasNext())
                System.out.println(fin.nextLine());
            fin.close();
            System.exit(0);
        }
        catch(Exception e)
        {
            System.err.println(e.getMessage());
            System.err.println("Error opening version file for reading.");
            System.exit(-1);
        }
    }

    private void printHelp()
    {
        try
        {
            Scanner fin = new Scanner("README.txt");
            while(fin.hasNext())
                System.out.println(fin.nextLine());
            fin.close();
            System.exit(0);
        }
        catch(Exception e)
        {
            System.err.println(e.getMessage());
            System.err.println("Error opening help file for reading.");
            System.exit(-1);
        }
    }

    private void setRotation(AbstractFlag f) throws InvalidCommandException {
        String param = f.getParameters().length >= 1 ? f.getParameters()[0] : "";
        try
        {
            rotation = Integer.parseInt(param);
        }
        catch(NumberFormatException nfe)
        {
            throw new InvalidCommandException("Not a valid parameter for -R/--rotate");
        }
    }

    private void getFilter(AbstractFlag f)
    {
        try
        {
            Scanner fin = new Scanner(f.getParameters().length >= 1 ? f.getParameters()[0] : "");
            while(fin.hasNext())
                filter += fin.nextLine();
            fin.close();
        }
        catch(Exception e)
        {
            System.err.println(e.getMessage());
            System.err.println("Error opening filter file");
            System.exit(-1);
        }
    }

    private void setFileSize(AbstractFlag f)
    {
        try
        {
            file_size = Long.parseLong(f.getParameters().length >= 1 ? f.getParameters()[0] : "");
        }
        catch(NumberFormatException nfe)
        {
            System.err.println("Not a valid parameter for flag -l/--limit");
            System.exit(-1);
        }
    }

    private void setBufferSize(AbstractFlag f)
    {

    }

    private void printDevices()
    {
        System.out.println("Printing available devices...");
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();
        int res = Pcap.findAllDevs(devices, errbuf);
        if(res == Pcap.NOT_OK || devices.isEmpty())
        {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            System.exit(-1);
        }
        System.out.println("Network devices found:");
        int i = 0;
        for(PcapIf device : devices)
        {
            String description = device.getDescription() != null ? device.getDescription() : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }
    }

    public void setCount(AbstractFlag f) throws InvalidCommandException {
        String c = f.getParameters().length >= 1 ? f.getParameters()[0] : "";
        try
        {
            count = Integer.parseInt(c);
            System.out.println("Set packet count to: " + count);
        }
        catch(NumberFormatException nfe)
        {
            throw new InvalidCommandException("Not a valid parameter for flag -c/--count");
        }
    }

    private void capture()
    {
        buildExpression();
        List<PcapIf> devices = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder();
        int r = Pcap.findAllDevs(devices, errbuf);
        if(r == Pcap.NOT_OK || devices.isEmpty())
        {
            System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
            System.exit(-1);
        }
        PcapIf device = null;
        if(!iface_name.equals(""))
            for(PcapIf d : devices)
                if(d.getName().equalsIgnoreCase(iface_name))
                    device = d;
        if(device == null)
            device = devices.get(cap_iface_int);
        if(device == null)
        {
            device = devices.get(0);
            System.out.printf("\nChoosing %s on your behalf:\n", device.getDescription() != null ? device.getDescription() : device.getName());
        }
        System.out.printf("\nChose %s to capture from:\n", device.getDescription() != null ? device.getDescription() : device.getName());
        int snaplen = 64 * 1024;
        int flags = mode;
        int timeout = 10 * 1000;
        Pcap pcap = null;
        if(!ifile.equals(""))
            pcap = Pcap.openOffline(ifile,errbuf);
        else
            pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        if(pcap == null)
        {
            System.err.printf("Error while opening device/file for capture: " + errbuf.toString());
            System.exit(-1);
        }
        if(!filter.equals(""))
        {
            PcapBpfProgram program = new PcapBpfProgram();
            if (pcap.compile(program, filter, 0, 0) != Pcap.OK) {
                System.err.println(pcap.getErr());
                System.exit(-1);
            }
            if (pcap.setFilter(program) != Pcap.OK) {
                System.err.println(pcap.getErr());
                System.exit(-1);
            }
        }
        Pattern p = null;
        if(!text_pattern.equals(""))
        {
            try
            {
                p = Pattern.compile(text_pattern);
            }
            catch(PatternSyntaxException pse)
            {
                System.err.println("Could not compile Java regex pattern");
            }
        }
        if(!ofile.equals(""))
        {
            int i = 1;
            PcapDumper dumper = pcap.dumpOpen(ofile);
            JBufferHandler<PcapDumper> handler = new JBufferHandler<PcapDumper>() {
                @Override
                public void nextPacket(PcapHeader pcapHeader, JBuffer jBuffer, PcapDumper pcapDumper) {
                    Pattern p = null;
                    if(!text_pattern.equals(""))
                    {
                        try
                        {
                            p = Pattern.compile(text_pattern);
                        }
                        catch(PatternSyntaxException pse)
                        {
                            System.err.println("Could not compile Java regex pattern");
                        }
                    }
                    if(p != null && print)
                    {
                        Matcher m = p.matcher(jBuffer.toHexdump(jBuffer.size(),true, true, true));
                        if(ASCII && m.find()) {
                            System.out.println(jBuffer.toHexdump(jBuffer.size(), true, true, true));
                            pcapDumper.dump(pcapHeader, jBuffer);
                        }
                        else if(m.find()) {
                            System.out.println(jBuffer.toHexdump(jBuffer.size(), true, false, true));
                            pcapDumper.dump(pcapHeader, jBuffer);
                        }

                    }
                    else if(print)
                    {
                        if(ASCII)
                            System.out.println(jBuffer.toHexdump(jBuffer.size(), true, true, true));
                        else
                            System.out.println(jBuffer.toHexdump(jBuffer.size(), true, false, true));
                        pcapDumper.dump(pcapHeader, jBuffer);
                    }
                    else
                        pcapDumper.dump(pcapHeader, jBuffer);
                }
            };
            pcap.loop(count == 0 ? Pcap.LOOP_INFINITE : count, handler, dumper);
            File out = new File(ofile + (i == 1 ? "" : i));
            if(out.length() >= file_size)
            {
                System.out.println("File size limit of " + file_size + " bytes has been reached\nOpening new dump file.");
                dumper.close();
                dumper = pcap.dumpOpen(ofile + i++);
                pcap.loop(count == 0 ? Pcap.LOOP_INFINITE : count, handler, dumper);
            }
            dumper.close();
            pcap.close();
        }
        else
        {
            PcapPacketHandler<String> handler = new PcapPacketHandler<String>() {
                @Override
                public void nextPacket(PcapPacket pcapPacket, String s) {
                    Pattern p = null;
                    if(!text_pattern.equals(""))
                    {
                        try
                        {
                            p = Pattern.compile(text_pattern);
                        }
                        catch(PatternSyntaxException pse)
                        {
                            System.err.println("Could not compile Java regex pattern");
                        }
                    }
                    if(p != null && print)
                    {
                        Matcher m = p.matcher(pcapPacket.toHexdump(pcapPacket.size(), true, true, true));
                        if(ASCII && m.find())
                            System.out.printf("Received packet at %s caplen=%-4d len=%-4d \nHeader: \n%s\n%s\n",
                                    new Date(pcapPacket.getCaptureHeader().timestampInMillis()),
                                    pcapPacket.getCaptureHeader().caplen(),
                                    pcapPacket.getCaptureHeader().wirelen(),
                                    pcapPacket.getCaptureHeader().toHexdump(pcapPacket.size(), true, true, true),
                                    pcapPacket.toHexdump(pcapPacket.size(), true, true, true));
                        else if(m.find())
                            System.out.printf("Received packet at %s caplen=%-4d len=%-4d \nHeader: \n%s\n%s\n",
                                    new Date(pcapPacket.getCaptureHeader().timestampInMillis()),
                                    pcapPacket.getCaptureHeader().caplen(),
                                    pcapPacket.getCaptureHeader().wirelen(),
                                    pcapPacket.getCaptureHeader().toHexdump(pcapPacket.size(), true, true, true),
                                    pcapPacket.toHexdump(pcapPacket.size(), true, false, true));
                    }
                    else if(print)
                    {
                        if(ASCII)
                            System.out.printf("Received packet at %s caplen=%-4d len=%-4d \nHeader: \n%s\n%s\n",
                                    new Date(pcapPacket.getCaptureHeader().timestampInMillis()),
                                    pcapPacket.getCaptureHeader().caplen(),
                                    pcapPacket.getCaptureHeader().wirelen(),
                                    pcapPacket.getCaptureHeader().toHexdump(pcapPacket.size(), true, true, true),
                                    pcapPacket.toHexdump(pcapPacket.size(), true, true, true));
                        else
                            System.out.printf("Received packet at %s caplen=%-4d len=%-4d \nHeader: \n%s\n%s\n",
                                    new Date(pcapPacket.getCaptureHeader().timestampInMillis()),
                                    pcapPacket.getCaptureHeader().caplen(),
                                    pcapPacket.getCaptureHeader().wirelen(),
                                    pcapPacket.getCaptureHeader().toHexdump(pcapPacket.size(), true, true, true),
                                    pcapPacket.toHexdump(pcapPacket.size(), true, false, true));
                    }
                }
            };
            pcap.loop(count == 0 ? Pcap.LOOP_INFINITE : count, handler, "jNetPcap rocks!");
            pcap.close();
        }
    }

    private void buildExpression()
    {
        filter = !src_string.equals("") ? src_string : "";
        filter += !dst_string.equals("")  && !src_string.equals("") ? " and " + dst_string : dst_string;
        filter += !port_string.equals("") && (!src_string.equals("") || !dst_string.equals("")) ? " and " + port_string : port_string;
        filter += !proto_string.equals("") && (!src_string.equals("") || !dst_string.equals("") || !port_string.equals("")) ? " and " + proto_string : proto_string;
        filter += !dir_string.equals("")  && (!src_string.equals("") || !dst_string.equals("") || !port_string.equals("") || !proto_string.equals("")) ? " and " + dir_string : dir_string;
        if(filter.contains("(") && filter.contains(")"))
        {
            filter = "'" + filter + "'";
        }
        System.out.println("Using the following filter expression: " + filter);
    }
}
