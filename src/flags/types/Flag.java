package flags.types;

import flags.InvalidCommandException;

import java.util.List;

public interface Flag
{
    public abstract void addParameters(String[] params);
    public abstract String[] getParameters();
    public abstract FlagType getType();
}
