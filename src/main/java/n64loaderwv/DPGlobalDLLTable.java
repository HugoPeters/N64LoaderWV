package n64loaderwv;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
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
import ghidra.program.model.address.AddressOverflowException;
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

public class DPGlobalDLLTable 
{
	private static HashMap<Integer, String> dll_names;
	
	private static class Info
	{
		public Info(long aConstantAddr, int aDllId)
		{
			constant_address = aConstantAddr;
			dll_id = aDllId;
			dll_name = null;
		}
		
		public Info(long aConstantAddr, int aDllId, String aName)
		{
			constant_address = aConstantAddr;
			dll_id = aDllId;
			dll_name = aName;
		}
		
		long constant_address;
		int dll_id;
		String dll_name;
	}
	
	private static void MakeConstant(Program p, Address addr) throws CodeUnitInsertionException
	{
		Data d = DataUtilities.createData(p, addr, PointerDataType.dataType, -1, false,
				ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

		MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.CONSTANT);
	}
	
	public static String GetGlobalDLLName(int aDllIndex)
	{
		return dll_names.get(aDllIndex);
	}
	
	public static void Build(Program aProgram, DPDLLTab aTab, long loadAddress, MessageLog aLog, TaskMonitor aMonitor) throws MemoryAccessException, InvalidInputException, CodeUnitInsertionException, IOException, AddressOverflowException, AddressOutOfBoundsException
	{
		Memory mem = aProgram.getMemory();

		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		outStream.write(new byte[0x1000]);
		byte[] data = outStream.toByteArray();
		InputStream inStream = new ByteArrayInputStream(data);

		AddressSpace addrSpace = aProgram.getAddressFactory().getDefaultAddressSpace();
		
		MemoryBlock block = MemoryBlockUtils.createInitializedBlock(
				aProgram, false, ".redir", addrSpace.getAddress(0x80800000),
				inStream, 0x1000, "Redirection table",
				null, true, true, true, aLog, aMonitor);

		outStream.close();

		AddressSpace redirSpace = block.getStart().getAddressSpace();

		Info infos[] = new Info[]
				{
					new Info(0x8008c994, 0x01, "cmdmenu"),
					new Info(0x8008c978, 0x02, "camcontrol"),
					new Info(0x8008c97c, 0x03, "ANIM"),
					new Info(0x8008c998, 0x04, "Race"),
					new Info(0x8008c99c, 0x05, "AMSEQ"),
					new Info(0x8008c9a0, 0x05, "AMSEQ"), // same as last
					new Info(0x8008c9a4, 0x06, "AMSFX"),
					new Info(0x8008c980, 0x07, "newday"),
					new Info(0x8008c984, 0x08, "newfog"),
					new Info(0x8008c988, 0x09, "newclouds"),
					new Info(0x8008c98c, 0x0A, "newstars"),
					new Info(0x8008c9a8, 0x0B, "newlfx"),
					new Info(0x8008c990, 0x0C, "minic"),
					new Info(0x8008c9b4, 0x0D, "expgfx"),
					new Info(0x8008c9b8, 0x0E, "modgfx"),
					new Info(0x8008c9bc, 0x0F, "projgfx"),
					new Info(0x8008c9c0, 0x10, null),
					new Info(0x8008c9c4, 0x11, "partfx"),
					new Info(0x8008c9c8, 0x12, "objfsa"),
					
					new Info(0x8008c9cc, 0x14, "SCREENS"),
					new Info(0x8008c9d0, 0x15, "text"),
					new Info(0x8008c9d4, 0x16, "subtitles"),
					new Info(0x8008c9d8, 0x17, null),
					new Info(0x8008c9dc, 0x18, "waterfx"),
					new Info(0x8008c9e0, 0x19, "paths"),
					new Info(0x8008c9e4, 0x1A, "CURVES"),
					new Info(0x8008c9f0, 0x1B, null),
					new Info(0x8008c974, 0x1C, "clrscr"),
					new Info(0x8008c9f4, 0x1D, "gplay"),
					new Info(0x8008c9fc, 0x1E, "tasktext"),
					new Info(0x8008ca00, 0x1F, "Save"),
					new Info(0x8008ca08, 0x20, null),
					new Info(0x8008ca0c, 0x21, null),
					
					new Info(0x8008ca14, 0x36, "pickup"),
					
					new Info(0x8008c9f8, 0x38, "putdown"),
					new Info(0x8008c9ac, 0x39, null),
					new Info(0x8008c9b0, 0x3A, null),
					new Info(0x8008ca10, 0x3B, null),

					new Info(0x8008c9e8, 0x4A, "picmenu"),
					new Info(0x8008c9ec, 0x4B, "frontend"),
					new Info(0x8008ca04, 0x4C, null),
				};
		
		dll_names = new HashMap<Integer, String>();

		long redirectionBlockAddress = 0x80800000;

		for (int i = 0; i < infos.length; ++i)
		{
			Info info = infos[i];
			int dllId = aTab.DecodeDLLId(info.dll_id);
			
			long dllAddress = 0x81000000;
			for (int j = 1; j < dllId; j++)
			{
				int tabOffset = aTab.dll_offsets.get(j - 1);
				int dllBss = aTab.dll_bss_sizes.get(j - 1);
				int dllSize = aTab.dll_offsets.get(j) - tabOffset;

				dllAddress += dllSize + dllBss;
				dllAddress = Utils.align(dllAddress, 0x1000);
			}

			Address addrDllEntry = addrSpace.getAddress(dllAddress + 0x18);

			// write the redirection table entry
			Address addrRedirTableEntry = redirSpace.getAddress(redirectionBlockAddress + i * 4);
			mem.setInt(addrRedirTableEntry, (int)addrDllEntry.getOffset());
			
			// set the global to the redirection address
			Address addrGlobal = addrSpace.getAddress(info.constant_address);
			mem.setInt(addrGlobal, (int)addrRedirTableEntry.getOffset());
			
			MakeConstant(aProgram, addrRedirTableEntry);
			MakeConstant(aProgram, addrGlobal);
			
			String globalName = "gDLL_";
			
			if (info.dll_name != null)
			{
				globalName += info.dll_name;
				dll_names.put(info.dll_id, info.dll_name);
			}
			else
			{
				globalName += String.format("%d", dllId);
			}
			
			aProgram.getSymbolTable().createLabel(addrGlobal, globalName, SourceType.ANALYSIS);
		}
	}
}
























