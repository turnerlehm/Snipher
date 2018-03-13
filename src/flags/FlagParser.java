package flags;

import flags.types.*;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class FlagParser
{
    private static FlagParser instance = null;
    private FlagParser(){}

    public static FlagParser getInstance()
    {
        if(instance == null)
        {
            synchronized (FlagParser.class)
            {
                if (instance == null)
                    instance = new FlagParser();
            }
        }
        return instance;
    }

    public List<AbstractFlag> parseFlags(String[] tokens)
    {
        List<AbstractFlag> flags = Collections.synchronizedList(new ArrayList<>());
        AbstractFlag f;
        FlagType flag;
        for(int i = 1; i < tokens.length; i++)
        {
            flag = validFlag(tokens[i]);
            switch(flag)
            {
                case ASCII:
                    f = new FlagASCII();
                    f.addParameters(new String[0]);
                    break;
                case BUFFER_SIZE:
                    f = new FlagBufferSize();
                    break;
                case COUNT:
                    f = new FlagCount();
                    break;
                case FILE_SIZE:
                    f = new FlagFileSize();
                    break;
                case DEVICES:
                    f = new FlagDevices();
                    f.addParameters(new String[0]);
                    break;
                case ROTATE:
                    f = new FlagRotate();
                    break;
                case HELP:
                    f = new FlagHelp();
                    f.addParameters(new String[0]);
                    break;
                case VERSION:
                    f = new FlagVersion();
                    f.addParameters(new String[0]);
                    break;
                case INTERFACE:
                    f = new FlagInterface();
                    break;
                case MON_MODE:
                    f = new FlagMonMode();
                    f.addParameters(new String[0]);
                    break;
                case MODE:
                    f = new FlagMode();
                    break;
                case PRINT:
                    f = new FlagPrint();
                    f.addParameters(new String[0]);
                    break;
                case DIRECTION:
                    f = new FlagDirection();
                    break;
                case IN_FILE:
                    f = new FlagInFile();
                    break;
                case OUT_FILE:
                    f = new FlagOutFile();
                    break;
                case PORT:
                    f = new FlagPort();
                    break;
                case PROTOCOL:
                    f = new FlagProtocol();
                    break;
                case SOURCE:
                    f = new FlagSource();
                    break;
                case DESTINATION:
                    f = new FlagDestination();
                    break;
                case UNBUFFERED:
                    f = new FlagUnbuffered();
                    f.addParameters(new String[0]);
                    break;
                case PATTERN:
                    f = new FlagPattern();
                    break;
                default:
                    f = new FlagInvalid();
                    f.addParameters(new String[0]);
                    break;
            }
            if(flag != FlagType.ASCII && flag != FlagType.DEVICES && flag != FlagType.HELP && flag != FlagType.VERSION
                    && flag != FlagType.MON_MODE && flag != FlagType.PRINT && flag != FlagType.UNBUFFERED
                    && flag != FlagType.INVALID && flag != FlagType.PATTERN)
                f.addParameters(parseParameters(tokens[i]));
            if(flag == FlagType.PATTERN)
                f.addParameters(getPattern(tokens[i]));
            flags.add(f);
        }
        return flags;
    }

    private String[] getPattern(String token)
    {
        String[] pattern = new String[1];
        pattern[0] = token.substring(token.indexOf('='));
        return pattern;
    }

    private String[] parseParameters(String flag)
    {
        String params = flag.substring(flag.indexOf('='));
        return params.split(",");
    }

    private FlagType validFlag(String input)
    {
        if(input.equals("-A") || input.equals("--ASCII"))
            return FlagType.ASCII;
        else if(input.startsWith("-B=") || input.startsWith("--buffer_size="))
            return FlagType.BUFFER_SIZE;
        else if(input.startsWith("-c=") || input.startsWith("--count="))
            return FlagType.COUNT;
        else if(input.startsWith("-l=") || input.startsWith("--limit="))
            return FlagType.FILE_SIZE;
        else if(input.equals("-d") || input.equals("--devices"))
            return FlagType.DEVICES;
        else if(input.startsWith("-R=") || input.startsWith("--rotate="))
            return FlagType.ROTATE;
        else if(input.equals("-h") || input.equals("--help"))
            return FlagType.HELP;
        else if(input.equals("-v") || input.equals("--version"))
            return FlagType.VERSION;
        else if(input.startsWith("-i=") || input.startsWith("--interface="))
            return FlagType.INTERFACE;
        else if(input.equals("-M") || input.equals("--monitor_mode"))
            return FlagType.MON_MODE;
        else if(input.startsWith("-m=") || input.equals("--mode="))
            return FlagType.MODE;
        else if(input.equals("-pr") || input.equals("--print"))
            return FlagType.PRINT;
        else if(input.startsWith("-d=") || input.equals("--direction="))
            return FlagType.DIRECTION;
        else if(input.startsWith("-in=") || input.startsWith("--input="))
            return FlagType.IN_FILE;
        else if(input.startsWith("-out=") || input.startsWith("--output="))
            return FlagType.OUT_FILE;
        else if(input.startsWith("-p=") || input.startsWith("--port="))
            return FlagType.PORT;
        else if(input.startsWith("-P=") || input.startsWith("--protocol="))
            return FlagType.PROTOCOL;
        else if(input.startsWith("-src=") || input.startsWith("--source="))
            return FlagType.SOURCE;
        else if(input.startsWith("-dst=") || input.startsWith("--destination="))
            return FlagType.DESTINATION;
        else if(input.equals("-U") || input.equals("--unbuffered"))
            return FlagType.UNBUFFERED;
        else if(input.startsWith("-pat=") || input.startsWith("--pattern="))
            return FlagType.PATTERN;
        else
            return FlagType.INVALID;
    }
}
