package sega;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

class MarsUserHeader implements StructConverter {
	private byte[] moduleName = null;
	private long version = 0;
	private long sourceAddress = 0;
	private long destinationAddress = 0;
	private long size = 0;
	private long sh2MasterStartAddress = 0;
	private long sh2SlaveStartAddress = 0;
	private long sh2MasterVectorBaseAddress = 0;
	private long sh2SlaveVectorBaseAddress = 0;

	MarsUserHeader(BinaryReader reader) throws IOException {

		if (reader.length() < 0x2d) {
			return;
		}

		reader.setPointerIndex(0x3c0);

		moduleName = reader.readNextByteArray(0x10);
		version = reader.readNextUnsignedInt();
		sourceAddress = reader.readNextUnsignedInt();
		destinationAddress = reader.readNextUnsignedInt();
		size = reader.readNextUnsignedInt();
		sh2MasterStartAddress = reader.readNextUnsignedInt();
		sh2SlaveStartAddress = reader.readNextUnsignedInt();
		sh2MasterVectorBaseAddress = reader.readNextUnsignedInt();
		sh2SlaveVectorBaseAddress = reader.readNextUnsignedInt();
	}

	@Override
	public DataType toDataType() {
		Structure s = new StructureDataType("MARSUserHeader", 0);

		s.add(STRING, 0x10, "moduleName", null);
		s.add(DWORD, 0x04, "version", null);
		s.add(POINTER, 0x04, "sourceAddress", null);
		s.add(POINTER, 0x04, "destinationAddress", null);
		s.add(DWORD, 0x04, "size", null);
		s.add(POINTER, 0x04, "sh2MasterStartAddress", null);
		s.add(POINTER, 0x04, "sh2SlaveStartAddress", null);
		s.add(POINTER, 0x04, "sh2MasterVectorBaseAddress", null);
		s.add(POINTER, 0x04, "sh2SlaveVectorBaseAddress", null);

		return s;
	}

	public byte[] getModuleName() {
		return moduleName;
	}

	public long getVersion() {
		return version;
	}

	public long getSourceAddress() {
		return sourceAddress;
	}

	public long getDestinationAddress() {
		return destinationAddress;
	}

	public long getSize() {
		return size;
	}

	public long getSh2MasterStartAddress() {
		return sh2MasterStartAddress;
	}

	public long getSh2SlaveStartAddress() {
		return sh2SlaveStartAddress;
	}

	public long getSh2MasterVectorBaseAddress() {
		return sh2MasterVectorBaseAddress;
	}

	public long getSh2SlaveVectorBaseAddress() {
		return sh2SlaveVectorBaseAddress;
	}
}
