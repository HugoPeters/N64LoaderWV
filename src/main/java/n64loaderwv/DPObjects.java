package n64loaderwv;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
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

public class DPObjects 
{
	public HashMap<Integer, String> dllidx_to_objname;
	
	public void Load(ByteArrayProvider s, DPDLLTab dlltab) throws IOException
	{
		BinaryReader handle = new BinaryReader(s, false);
		
		int rom_OBJECTS_BIN_offset = 0x37EEB42; 
		int rom_OBJECTS_TAB_offset = 0X37ED766;
		
		// read tab
		List<Integer> offsets = new ArrayList<Integer>();
		
		handle.setPointerIndex(rom_OBJECTS_TAB_offset);
		
		while (true)
		{
			int objOffset = handle.readNextInt();
			
			if (objOffset == -1)
				break;
			
			offsets.add(rom_OBJECTS_BIN_offset + objOffset);
		}
		
		// read bin
		dllidx_to_objname = new HashMap<Integer, String>();
		
		// it might make more sense to present the DLL ids as how they appear in objects.bin
		// but it's also useful to just have the index into DLLS.TAB

		for (int i = 0; i < offsets.size(); ++i)
		{
			int dllRawId = handle.readShort(offsets.get(i) + 0x58) & 0xFFFF;
			
			if (dllRawId == 0)
				continue; // note, -1 in SFA
			
			int dllIndex = dlltab.DecodeDLLId(dllRawId);
			
			String objName = handle.readTerminatedString(offsets.get(i) + 0x5F, (char)0);
			
			dllidx_to_objname.put(dllIndex, objName);
		}
	}
}
























