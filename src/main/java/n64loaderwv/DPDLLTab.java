package n64loaderwv;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.python.jline.internal.Log;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DPDLLTab
{
	public int[] dll_banks;
	public List<Integer> dll_offsets;
	
	public void Load(ByteArrayProvider s) throws IOException, InvalidInputException
	{
		BinaryReader handle = new BinaryReader(s, false);
		
		int offset_DLLS_TAB = 0x3B04BDC;
		
		// read tab
		handle.setPointerIndex(offset_DLLS_TAB);
		
		dll_banks = new int[4];
		dll_banks[0] = handle.readNextInt();
		dll_banks[1] = handle.readNextInt();
		dll_banks[2] = handle.readNextInt();
		dll_banks[3] = handle.readNextInt();
		
		// according to the game the first dll actually starts at 0x8 but this is bank data
		// not sure why
		// ignore this and just make correct offsets, we fix the ID later by just adding 1
		
		dll_offsets = new ArrayList<Integer>();
		
		while (true) 
		{
			int dllOffset = handle.readNextInt();
			int dllUnk = handle.readNextInt();
			
			if (dllOffset == -1 && dllUnk == -1)
				break;
			
			dll_offsets.add(dllOffset);
		}
	}
	
	public int GetDLLRomOffsetFromIndex(int aIndex)
	{
		int offset_DLLS_BIN = 0x38317CC;
		int tabOffset = dll_offsets.get(aIndex);
		int dllOffset = offset_DLLS_BIN + tabOffset;
		return dllOffset;
	}
	
	public int GetDLLRomOffsetFromEncodedId(int aId)
	{
		int index = DecodeDLLId(aId);
		return GetDLLRomOffsetFromIndex(index - 1);
	}
	
	public int DecodeDLLId(int aId)
	{
		int index = aId;
		
		if (aId >= 0x8000)
		{
			index = (aId - 0x8000) + dll_banks[3];
		}
		else if (aId >= 0x2000)
		{
			index = (aId - 0x1FFF) + dll_banks[1];
		}
		else if (aId >= 0xFFF)
		{
			index = (aId - 0xFFF) + dll_banks[0];
		}
		
		return index;
	}
}
























