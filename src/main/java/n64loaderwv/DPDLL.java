package n64loaderwv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.io.output.ByteArrayOutputStream;
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

import n64loaderwv.Utils;

public class DPDLL 
{
	private Program program;
	public int dll_id;
	public int dll_rom_offset;
	public int dll_tab_offset;
	public int dll_bss;
	public int dll_size;
	public int hdr_size;
	public int hdr_offset_data;
	public int hdr_offset_rodata; // begins with relocation table
	public short hdr_export_count;
	public int code_offset;
	public int code_size;
	public int rodata_offset;
	private long load_address;
	private long code_address;
	private long rodata_address;
	private long data_address;
	private AddressSpace address_space;
	public String dll_identifier;
	public String dll_block_name;

	private int GetHeaderInitFuncOffset()
	{
		return 0x10;
	}

	private int GetHeaderFiniFuncOffset()
	{
		return 0x14;
	}

	private int GetHeaderExportFuncOffset(int idx)
	{
		return 0x1C + 4 * idx;
	}
	
	public DPDLL(Program aProgram, int aId, int aRomStartOffset, int aTabOffset, int aBssSize, int aSize)
	{
		program = aProgram;
		dll_id = aId;
		dll_rom_offset = aRomStartOffset;
		dll_tab_offset = aTabOffset;
		dll_bss = aBssSize;
		dll_size = aSize;
		address_space = program.getAddressFactory().getDefaultAddressSpace();
	}
	
	public void Load(ByteArrayProvider s, long loadAddress, MessageLog log, TaskMonitor monitor, DPObjects objects) throws IOException, InvalidInputException
	{
		load_address = loadAddress;
		
		BinaryReader handle = new BinaryReader(s, false);
		
		handle.setPointerIndex(dll_rom_offset);
		hdr_size = handle.readNextInt();
		hdr_offset_data = handle.readNextInt();
		hdr_offset_rodata = handle.readNextInt();
		hdr_export_count = handle.readNextShort();
		code_offset = hdr_size;
		code_size = dll_size - hdr_size;

		Log.info(String.format("DP: DLL %d @ 0x%08X", dll_id, dll_rom_offset));

		code_address = load_address + code_offset;
		rodata_address = load_address + hdr_offset_rodata;
		data_address = load_address + hdr_offset_data;

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
			
			ByteArrayOutputStream out_stream = new ByteArrayOutputStream();
			out_stream.write(s.readBytes(dll_rom_offset, dll_size));
			out_stream.write(new byte[dll_bss]);
			byte[] dll_data = out_stream.toByteArray();
			InputStream in_stream = new ByteArrayInputStream(dll_data);
			
			MemoryBlock block = MemoryBlockUtils.createInitializedBlock(
					program, false, "." + dll_block_name, address_space.getAddress(load_address),
					in_stream, dll_size + dll_bss, dllBlockDesc,
					null, true, true, true, log, monitor);
			
			address_space = block.getStart().getAddressSpace();
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
		for (int i = 0; i < hdr_export_count + 2; ++i)
		{
			int exportOffset = 0;
			if (i == 0) exportOffset = GetHeaderInitFuncOffset();
			else if (i == 1) exportOffset = GetHeaderFiniFuncOffset();
			else exportOffset = GetHeaderExportFuncOffset(i - 2);

			long offsetAddr = load_address + exportOffset;
			int funcOffset = handle.readInt(dll_rom_offset + exportOffset);
			long funcAddress = code_address + funcOffset;
			Address writeAddr = address_space.getAddress(offsetAddr);
			mem.setInt(writeAddr, (int)funcAddress);
			Utils.MakeConstantPtr(program, writeAddr);

			functions.add(new FuncInfo(true, false, funcOffset));
		}
		
		// relocation table
		if (hdr_offset_rodata != -1)
		{
			Register reg = program.getLanguage().getRegister("gp");
			Address regAddrStart = address_space.getAddress(load_address);
			Address regAddrEnd = address_space.getAddress(load_address + dll_size + dll_bss - 1);
			ctx.setValue(reg, regAddrStart, regAddrEnd, BigInteger.valueOf(rodata_address));
			
			handle.setPointerIndex(dll_rom_offset + hdr_offset_rodata);
			
			int rom_DLLSIMPORTTAB_offset = DPFST.offsets.get(72);
			
			long writeAddress = rodata_address - 4;
			
			// rodata table
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
				Utils.MakeConstantPtr(program, targetAddr);
			}
			
			// text table
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

			if (hdr_offset_data != -1)
			{
				// data table
				while (true)
				{
					int val = handle.readNextInt();

					if (val == -1)
						break;

					writeAddress = data_address + val;
		
					long writeValue = handle.readUnsignedInt(dll_rom_offset + hdr_offset_data + val);
					writeValue += data_address;
		
					Address targetAddr = address_space.getAddress(writeAddress);

					mem.setInt(targetAddr, (int)writeValue);
					Utils.MakeNormalPtr(program, targetAddr);
				}
			}
		}
		// end of table
		
		// create functions
		short rodataAddressHi = (short)((rodata_address >> 0x10) & 0xFFFF);
		short rodataAddressLo = (short)(rodata_address & 0xFFFF);
		
		for (int i = 0; i < functions.size(); ++i)
		{
			FuncInfo info = functions.get(i);
			String funcStrFlags = "";
			
			if (info.is_local)
				funcStrFlags += "L";
			if (info.is_export)
				funcStrFlags += "E";

			String funcName = null;
			if (i == 0) funcName = String.format("%s_init", dll_block_name);
			else if (i == 1) funcName = String.format("%s_fini", dll_block_name);
			else funcName = String.format("%s_func_%04d", dll_block_name, i - 2);

			if (funcStrFlags.length() > 0)
				funcName += "_" + funcStrFlags;
			
			Address addr = address_space.getAddress(code_address + info.dll_offset);
		    program.getSymbolTable().createLabel(addr, funcName, SourceType.ANALYSIS);
			program.getSymbolTable().addExternalEntryPoint(addr);
		    
		    if (info.is_local && hdr_offset_rodata != -1)
		    {
		    	// patch the GP register instructions at the start of the function
		    	// the game does this as well at runtime
		    	Address loadInstrPatchAddr = addr.add(2);
		    	Address orInstrPatchAddr = addr.add(6);
			mem.setShort(loadInstrPatchAddr, rodataAddressHi);
			mem.setShort(orInstrPatchAddr, rodataAddressLo);
		    }
		}
	}
}
























