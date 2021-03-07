package n64loaderwv;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;

public final class Utils
{
	public static long align(long value, long alignment)
	{
		return value >= 0 ? ((value + alignment - 1) / alignment) * alignment : (value / alignment) * alignment;
	}

	public static void MakeConstantPtr(Program p, Address addr) throws CodeUnitInsertionException
	{
		Data d = DataUtilities.createData(p, addr, PointerDataType.dataType, -1, false,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

		// you have no idea how long it took me to find how to fucking set this property
		MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.CONSTANT);
	}

	public static void MakeNormalPtr(Program p, Address addr) throws CodeUnitInsertionException
	{
		Data d = DataUtilities.createData(p, addr, PointerDataType.dataType, -1, false,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

	}
}
