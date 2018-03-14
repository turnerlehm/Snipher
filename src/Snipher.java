import flags.FlagParser;
import flags.InvalidCommandException;

public class Snipher
{
    public static void main(String[] args) throws InvalidCommandException
    {
        CommandExecutor ce = CommandExecutor.getInstance();
        FlagParser fp = FlagParser.getInstance();
        ce.setParser(fp);
        System.out.println("Passed in arguments:");
        for(String s : args)
            System.out.print(s + " ");
        System.out.println();
        ce.execute(args);
    }
}
