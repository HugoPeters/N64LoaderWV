package n64loaderwv;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.util.exception.InvalidInputException;

public final class DPFST
{
	public static List<Integer> offsets;

	public static void Load(ByteArrayProvider s, int offset_FST) throws IOException, InvalidInputException
	{
		BinaryReader handle = new BinaryReader(s, false);

		handle.setPointerIndex(offset_FST);

		int count = handle.readNextInt();
		int offset_FAT = offset_FST + (count + 2) * 4;

		offsets = new ArrayList<Integer>();

		for (int i = 0; i < count + 1; i++)
		{
			int offset = handle.readNextInt();

			offsets.add(offset_FAT + offset);
		}
	}
}
