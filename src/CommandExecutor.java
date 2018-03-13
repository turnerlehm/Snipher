import flags.FlagParser;
import flags.InvalidCommandException;
import flags.types.AbstractFlag;
import flags.types.FlagType;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.PcapDumper;

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
    private volatile int file_size = 0;
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
        }
        capture();
    }

    private void setTextPattern(AbstractFlag f) throws InvalidCommandException {
        text_pattern = f.getParameters()[0];
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
            dst_string = "src " + params[0];
        }
        else
        {
            dst_string = "(";
            for(int i = 0; i < params.length; i++)
            {
                if(i != params.length - 1)
                    dst_string += params[i] + " || ";
                else
                    dst_string += params[i] + ")";
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
            src_string = "(";
            for(int i = 0; i < params.length; i++)
            {
                if(i != params.length - 1)
                    src_string += params[i] + " || ";
                else
                    src_string += params[i] + ")";
            }
        }
    }

    private void setProtocol(AbstractFlag f)
    {
        String[] params = f.getParameters();
        if(params.length == 1)
            proto_string = params[0];
        else
        {
            proto_string = "(";
            for(int i = 0; i < params.length; i++)
            {
                if(i != params.length - 1)
                    proto_string += params[i] + " || ";
                else
                    proto_string += params[i] + ")";
            }
        }
    }

    private void setListeningPorts(AbstractFlag f)
    {
        String[] params = f.getParameters();
        if(params.length == 1)
            port_string = "port " + params[0];
        else
        {
            port_string = "(";
            for(int i = 0; i < params.length; i++)
            {
                if(i != params.length - 1)
                    port_string += params[i] + " || ";
                else
                    port_string += params[i] + ")";
            }
        }
    }

    private void setOutput(AbstractFlag f) throws InvalidCommandException {
        String fname = f.getParameters().length >= 1 ? f.getParameters()[0] : "";
        File temp = new File(fname);
        if(temp.exists())
            throw new InvalidCommandException("File " + fname + " already exists.");
        ofile = fname;
    }

    private void setInput(AbstractFlag f) throws InvalidCommandException {
        String fname = f.getParameters()[0];
        File temp = new File(fname);
        if(!temp.exists())
            throw new InvalidCommandException("File " + fname + " does not exist");
        ifile = fname;
    }

    private void setDirection(AbstractFlag f)
    {
        dir_string = f.getParameters()[0];
    }

    private void setDeviceMode(AbstractFlag f)
    {
        String mode = f.getParameters()[0];
        if(mode.equals("PROMISCUOUS"))
            this.mode = Pcap.MODE_PROMISCUOUS;
        else if(mode.equals("!PROMISCUOUS"))
            this.mode = Pcap.MODE_NON_PROMISCUOUS;
    }

    private void setCaptureInterface(AbstractFlag f)
    {
        String iface = f.getParameters()[0];
        try
        {
            cap_iface_int = Integer.parseInt(iface);
        }
        catch(NumberFormatException nfe)
        {
            iface_name = iface;
        }
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
            Scanner fin = new Scanner("HELP.txt");
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
        String param = f.getParameters()[0];
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
            Scanner fin = new Scanner(f.getParameters()[0]);
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
            file_size = Integer.parseInt(f.getParameters()[0]);
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
        try
        {
            count = Integer.parseInt(f.getParameters()[0]);
        }
        catch(NumberFormatException nfe)
        {
            throw new InvalidCommandException("Not a valid parameter for flag -c/--count");
        }
    }

    private void capture()
    {

    }

    private void buildExpression()
    {
        filter = !src_string.equals("") ? src_string : "";
        filter += !dst_string.equals("") ? " and " + dst_string : "";
        filter += !port_string.equals("") ? " and " + port_string : "";
        filter += !proto_string.equals("") ? " and " + proto_string : "";
        filter += !dir_string.equals("") ? " and " + dir_string : "";
        if(filter.contains("(") && filter.contains(")"))
        {
            filter = "'" + filter + "'";
        }
    }
}
