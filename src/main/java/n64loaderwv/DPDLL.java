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
	public int code_offset;
	public int code_size;
	public int constants_offset;
	private long dll_address;
	private long code_address;
	private AddressSpace address_space;
	private long load_address;
	public String dll_identifier;
	public String dll_block_name;
	
	private long MakeRomAddress(int romOffset)
	{
		return load_address + (romOffset - 0x1000);
	}
	
	private int GetHeaderExportFuncOffset(int idx)
	{
		return dll_rom_offset + 16 + 4 * idx;
	}
	
	private long GetFunctionAddress(int aOffset)
	{
		// every(?) DLL function starts with some code that's patched by the game
		// it sets up the gp register for the function
		// atm we just set the register value, we could also patch the instructions
		int addFuncOffset = 0;// aIsExport ? 0xC : 0;
		
		long funcAddr = code_address + aOffset + addFuncOffset;
		
		return funcAddr;
	}
	
	// move to some utility thing
	private static void MakeConstantPtr(Program p, Address addr) throws CodeUnitInsertionException
	{
		Data d = DataUtilities.createData(p, addr, PointerDataType.dataType, -1, false,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

		// you have no idea how long it took me to find how to fucking set this property
		MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.CONSTANT);
	}
	
	public DPDLL(Program aProgram, int aId, int aRomStartOffset, int aTabOffset, int aSize) 
	{
		program = aProgram;
		dll_id = aId;
		dll_rom_offset = aRomStartOffset;
		dll_tab_offset = aTabOffset;
		dll_size = aSize;
		address_space = program.getAddressFactory().getDefaultAddressSpace();
	}
	
	public void Load(ByteArrayProvider s, long loadAddress, MessageLog log, TaskMonitor monitor, DPObjects objects) throws IOException, InvalidInputException
	{
		load_address = loadAddress;
		
		BinaryReader handle = new BinaryReader(s, false);
		
		handle.setPointerIndex(dll_rom_offset);
		hdr_size = handle.readNextInt();
		hdr_offset_data2 = handle.readNextInt(); // can be -1
		hdr_offset_constants = handle.readNextInt();
		hdr_unk1 = handle.readNextShort();
		code_offset = dll_rom_offset + hdr_size;
		code_size = dll_size - hdr_size;
		constants_offset = dll_rom_offset + hdr_offset_constants;
		
		Log.info(String.format("DP: DLL %d @ 0x%08X", dll_id, dll_rom_offset));

		dll_address = MakeRomAddress(dll_rom_offset);
		code_address = MakeRomAddress(code_offset);
		//constants_address = MakeRomAddress(dll_rom_offset + hdr_offset_constants);
		
		dll_identifier = String.format("dll_%03d", dll_id);
		dll_block_name = dll_identifier;
		String usedObjectName = null;
		
		if (objects.dllidx_to_objname.containsKey(dll_id))
		{
			usedObjectName = objects.dllidx_to_objname.get(dll_id);
			dll_block_name += String.format("_obj.%s", usedObjectName);
		}
		else
		{
			String globalDllName = DPGlobalDLLTable.GetGlobalDLLName(dll_id);
			
			if (globalDllName != null)
			{
				dll_block_name += String.format(".%s", globalDllName);
			}
		}
		
		try
		{
			String dllBlockDesc = String.format("DLL %d (used object=%s), ROM address 0x%08X, DLLS.BIN offset 0x%08X, DLLS.TAB offset 0x%08X"
											, dll_id, usedObjectName != null ? usedObjectName : "NONE", dll_rom_offset, dll_tab_offset, 0x10 + dll_id * 8);
			
			MemoryBlockUtils.createInitializedBlock(
					program, false, "." + dll_block_name, address_space.getAddress(code_address), 
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
	}
	
	private class FuncInfo
	{
		public boolean is_export;
		public boolean is_local;
		public int dll_offset;
		
		public FuncInfo(boolean aIsExport, boolean aIsLocal, int aOffset)
		{
			is_export = aIsExport;
			is_local = aIsLocal;
			dll_offset = aOffset;
		}
	}
	
	public void Relocate(ByteArrayProvider s) throws IOException, MemoryAccessException, AddressOutOfBoundsException, ContextChangeException, CodeUnitInsertionException, InvalidInputException
	{
		BinaryReader handle = new BinaryReader(s, false);

		Memory mem = program.getMemory();
		ProgramContext ctx = program.getProgramContext();
		
		List<FuncInfo> functions = new ArrayList<FuncInfo>();
		
		// patch the export function offsets to address of the func in the rom
		int num_exports = (hdr_size - 16) / 4;
		
		for (int i = 0; i < num_exports; ++i)
		{
			int exportOffset = GetHeaderExportFuncOffset(i);
			long offsetAddr = MakeRomAddress(exportOffset);
			int funcOffset = handle.readInt(exportOffset);
			long funcAddress = GetFunctionAddress(funcOffset);
			Address writeAddr = address_space.getAddress(offsetAddr);
			mem.setInt(writeAddr, (int)funcAddress);
			MakeConstantPtr(program, writeAddr);
			
			functions.add(new FuncInfo(true, false, funcOffset));
		}

		long dataAddress = dll_address + hdr_offset_constants;
		long writeAddress = dataAddress - 4;
		
		Register reg = program.getLanguage().getRegister("gp");
		Address regAddrStart = address_space.getAddress(dll_address);
		Address regAddrEnd = address_space.getAddress(dll_address + dll_size);
		ctx.setValue(reg, regAddrStart, regAddrEnd, BigInteger.valueOf(dataAddress));
		
		handle.setPointerIndex(dll_rom_offset + hdr_offset_constants);
		
		int rom_DLLSIMPORTTAB_offset = 0x3B064DC;
		
		// imports table
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
			MakeConstantPtr(program, targetAddr);
		}
		
		// function table
		while (true)
		{
			int val = handle.readNextInt();
			
			if (val == -3)
				break;
			
			boolean hasFunc = false;
			for (int i = 0; i < functions.size() && !hasFunc; ++i)
			{
				if (functions.get(i).dll_offset == val)
				{
					hasFunc = true;
					functions.get(i).is_local = true;
				}
			}
			
			if (!hasFunc)
			{
				functions.add(new FuncInfo(false, true, val));
			}
		}
		
		while (true)
		{
			int val = handle.readNextInt();
			
			if (val == -1)
				break;
			
			// offsets into the DLL to tables of more values?
		}
		
		// end of table
		
		// create functions
		short dataAddressHi = (short)((dataAddress >> 0x10) & 0xFFFF);
		short dataAddressLo = (short)(dataAddress & 0xFFFF);
		
		for (int i = 0; i < functions.size(); ++i)
		{
			FuncInfo info = functions.get(i);
			String funcStrFlags = "";
			
			if (info.is_local)
				funcStrFlags += "L";
			if (info.is_export)
				funcStrFlags += "E";

			String funcName = String.format("%s_func_%04d", dll_block_name, i);
			
			if (funcStrFlags.length() > 0)
				funcName += "_" + funcStrFlags;
			
			Address addr = address_space.getAddress(GetFunctionAddress(info.dll_offset));
		    program.getSymbolTable().createLabel(addr, funcName, SourceType.ANALYSIS);
			program.getSymbolTable().addExternalEntryPoint(addr);
		    
		    if (info.is_local)
		    {
		    	// patch the GP register instructions at the start of the function
		    	// the game does this as well at runtime
		    	Address loadInstrPatchAddr = addr.add(2);
		    	Address orInstrPatchAddr = addr.add(6);
		    	mem.setShort(loadInstrPatchAddr, dataAddressHi);
		    	mem.setShort(orInstrPatchAddr, dataAddressLo);
		    }
		}
	}
}
























