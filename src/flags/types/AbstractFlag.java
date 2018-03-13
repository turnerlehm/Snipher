package flags.types;

import flags.InvalidCommandException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public abstract class AbstractFlag implements Flag
{
    public final FlagType type;
    private List<FlagType> flags;
    private String[] parameters;

    protected AbstractFlag(FlagType type)
    {
        this.type = type;
        flags = Collections.synchronizedList(new ArrayList<>());
    }
    public void addFlag(FlagType flag) throws InvalidCommandException
    {
        if(flags.contains(flag))
            throw new InvalidCommandException("Flag has already been set");
        flags.add(flag);
    }

    public void addParameters(String[] params) {
        this.parameters = params;
    }

    public String[] getParameters() {
        return parameters;
    }

    public List<FlagType> getFlags() {
        return flags;
    }

    public FlagType getType() {
        return type;
    }
}
