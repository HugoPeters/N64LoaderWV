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
import ghidra.docking.settings.SettingsDefinition;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.code.CodeManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class DPDLL 
{
	private Program program;
	public int dll_id;
	public int dll_rom_offset;
	public int dll_tab_offset;
	public int dll_size;
	public int hdr_size;
	public int hdr_offset_data2;
	public int hdr_offset_constants; // includes import/export function table
	public short hdr_unk1;
	List<Integer> hdr_func_offsets;
	public int code_offset;
	public int code_size;
	public int constants_offset;
	public int constants_size;
	private long dll_address;
	private long code_address;
	private long constants_address;
	private AddressSpace address_space;
	
	public DPDLL(Program aProgram, int aId, int aRomStartOffset, int aTabOffset, int aSize) 
	{
		program = aProgram;
		hdr_func_offsets = new ArrayList<Integer>();
		dll_id = aId;
		dll_rom_offset = aRomStartOffset;
		dll_tab_offset = aTabOffset;
		dll_size = aSize;
		address_space = program.getAddressFactory().getDefaultAddressSpace();
	}
	
	public void Load(ByteArrayProvider s, long loadAddress, MessageLog log, TaskMonitor monitor, DPObjects objects) throws IOException, InvalidInputException
	{
		BinaryReader handle = new BinaryReader(s, false);
		
		handle.setPointerIndex(dll_rom_offset);
		hdr_size = handle.readNextInt();
		hdr_offset_data2 = handle.readNextInt();
		hdr_offset_constants = handle.readNextInt();
		hdr_unk1 = handle.readNextShort();
		code_offset = dll_rom_offset + hdr_size;
		code_size = dll_size - hdr_size;
		constants_offset = dll_rom_offset + hdr_offset_constants;
		constants_size = hdr_offset_data2 - hdr_offset_constants;
		
		int numFuncs = (hdr_size - 16) / 4;

		for (int i = 0; i < numFuncs; ++i)
		{
			int funcOffs = handle.readInt(dll_rom_offset + 16 + 4 * i);
			hdr_func_offsets.add(funcOffs);
		}
		
		Log.info(String.format("DP: DLL %d @ 0x%08X: %d functions", dll_id, dll_rom_offset, hdr_func_offsets.size()));

		dll_address = loadAddress + (dll_rom_offset - 0x1000);
		code_address = loadAddress + (code_offset - 0x1000);
		constants_address = loadAddress + (dll_rom_offset + hdr_offset_constants - 0x1000);
		
		String dllIdentifier = String.format("dll_%03d", dll_id);
		String dllBlockName = dllIdentifier;
		String usedObjectName = null;
		
		if (objects.dllidx_to_objname.containsKey(dll_id))
		{
			usedObjectName = objects.dllidx_to_objname.get(dll_id);
			dllBlockName += String.format("_obj.%s", usedObjectName);
		}
		
		try
		{
			String dllBlockDesc = String.format("DLL %d (used object=%s), ROM address 0x%08X, DLLS.BIN offset 0x%08X, DLLS.TAB offset 0x%08X"
											, dll_id, usedObjectName != null ? usedObjectName : "NONE", dll_rom_offset, dll_tab_offset, 0x10 + dll_id * 8);
			
			MemoryBlockUtils.createInitializedBlock(
					program, false, "." + dllBlockName, address_space.getAddress(code_address), 
					s.getInputStream(code_offset), code_size, dllBlockDesc, 
					null, true, true, true, log, monitor);
			
			// constants block
			/*String constantsBlockName = String.format(".%s_constants", dllIdentifier);
			Address constantsStartAddr = address_space.getAddress(constants_address);
			Address constantsEndAddr = address_space.getAddress(constants_address + constants_size);

			MemoryBlockUtils.createInitializedBlock(
					program, false, constantsBlockName, constantsStartAddr, 
					s.getInputStream(constants_offset), constants_size, null, 
					null, true, false, false, log, monitor);*/
			
			// mark constant data as constant, helps ghidra show noice function calls
			/*Address constantsStartAddr = address_space.getAddress(constants_address);
			Address constantsEndAddr = address_space.getAddress(constants_address + constants_size);
			
			AddressSetView addrSetConstantData = new AddressSet(constantsStartAddr, constantsEndAddr);
			DataIterator dataIt = program.getListing().getData(addrSetConstantData, true);
			
			while (dataIt.hasNext())
			{
				Data data = dataIt.next();
				
				// this only works before the data is analyzed, we probably need to CreateData explicitly
				MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.CONSTANT);
			}*/
		}
		catch (Exception e) 
		{
			Msg.error(this, ExceptionUtils.getStackTrace(e));
		}
		
		for (int j = 0; j < numFuncs; ++j)
		{
			if (j > 0 && hdr_func_offsets.get(j) == 0x0)
				continue; // nullfunc
			
			// every(?) DLL function starts with some code that's patched by the game
			// it sets up the gp register for the function
			// atm we just set the register value, we could also patch the instructions
			int addFuncOffset = 0xC;
			
			long funcAddr = code_address + hdr_func_offsets.get(j) + addFuncOffset;
			String funcName = String.format("%s_func_%04d", dllBlockName, j);
			
			Address addr = address_space.getAddress(funcAddr);
			program.getSymbolTable().addExternalEntryPoint(addr);
		    program.getSymbolTable().createLabel(addr, funcName, SourceType.ANALYSIS);
		}
	}
	
	public void Relocate(ByteArrayProvider s) throws IOException, MemoryAccessException, AddressOutOfBoundsException, ContextChangeException, CodeUnitInsertionException
	{
		BinaryReader handle = new BinaryReader(s, false);

		Memory mem = program.getMemory();
		ProgramContext ctx = program.getProgramContext();

		long dataAddress = dll_address + hdr_offset_constants;
		long writeAddress = dataAddress - 4;
		
		Register reg = program.getLanguage().getRegister("gp");
		Address regAddrStart = address_space.getAddress(dll_address);
		Address regAddrEnd = address_space.getAddress(dll_address + dll_size);
		ctx.setValue(reg, regAddrStart, regAddrEnd, BigInteger.valueOf(dataAddress));
		
		handle.setPointerIndex(dll_rom_offset + hdr_offset_constants);
		
		int rom_DLLSIMPORTTAB_offset = 0x3B064DC;
		
		while (true)
		{
			writeAddress += 4;
			int val = handle.readNextInt();

			if (val == -2)
				break;
			
			long writeValue = 0;
			
			if ((val & 0x80000000) == 0)
			{
				// pointer to address within DLL, string table, etc.
				writeValue = code_address + val;
			}
			else
			{
				// pointer to main executable function
				int importTabOffset = (val & 0x7FFFFFFF) * 4 - 4;
				writeValue = handle.readUnsignedInt(rom_DLLSIMPORTTAB_offset + importTabOffset); 
			}
			
			Address targetAddr = address_space.getAddress(writeAddress);
			
			mem.setInt(targetAddr, (int)writeValue);
			
			Data d = DataUtilities.createData(program, targetAddr, PointerDataType.dataType, -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			
			// you have no idea how long it took me to find how to fucking set this property
			MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.CONSTANT);
		}
		
		while (true)
		{
			int val = handle.readNextInt();
			
			if (val == -3)
				break;
			
			// TODO
		}
		
		while (true)
		{
			int val = handle.readNextInt();
			
			if (val == -1)
				break;
			
			// TODO
		}
		
		// end of table
	}
}
























