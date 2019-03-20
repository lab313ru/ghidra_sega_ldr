package sega;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class GameHeader implements StructConverter {
    private byte[] consoleName = null;
    private byte[] releaseDate = null;
    private byte[] domesticName = null;
    private byte[] internationalName = null;
    private byte[] version = null;
    private short checksum = 0;
    private byte[] ioSupport = null;
    private Address romStart = null, romEnd = null;
    private Address ramStart = null, ramEnd = null;
    private byte[] sramCode = null;
    private byte unused = 0;
    private Address sramStart = null, sramEnd = null;
    private byte[] notes = null;

    FlatProgramAPI fpa;
    
    public GameHeader(FlatProgramAPI fpa, BinaryReader reader) throws IOException {
        this.fpa = fpa;
        
        if (reader.length() < 0x200) {
            return;
        }
        
        reader.setPointerIndex(0x100);
        
        consoleName = reader.readNextByteArray(0x10);
        releaseDate = reader.readNextByteArray(0x10);
        domesticName = reader.readNextByteArray(0x30);
        internationalName = reader.readNextByteArray(0x30);
        version = reader.readNextByteArray(0x0E);
        checksum = (short) reader.readNextUnsignedShort();
        ioSupport = reader.readNextByteArray(0x10);
        romStart = fpa.toAddr(reader.readNextUnsignedInt());
        romEnd = fpa.toAddr(reader.readNextUnsignedInt());
        ramStart = fpa.toAddr(reader.readNextUnsignedInt());
        ramEnd = fpa.toAddr(reader.readNextUnsignedInt());
        sramCode = reader.readNextByteArray(0x03);
        unused = reader.readNextByte();
        sramStart = fpa.toAddr(reader.readNextUnsignedInt());
        sramEnd = fpa.toAddr(reader.readNextUnsignedInt());
        notes = reader.readNextByteArray(0x44);
    }
    
    @Override
    public DataType toDataType() {
        Structure s = new StructureDataType("GameHeader", 0);
        
        s.add(STRING, 0x10, "ConsoleName", null);
        s.add(STRING, 0x10, "ReleaseDate", null);
        s.add(STRING, 0x30, "DomesticName", null);
        s.add(STRING, 0x30, "InternationalName", null);
        s.add(STRING, 0x0E, "Version", null);
        s.add(WORD, 0x02, "Checksum", null);
        s.add(STRING, 0x10, "IoSupport", null);
        s.add(POINTER, 0x04, "RomStart", null);
        s.add(POINTER, 0x04, "RomEnd", null);
        s.add(POINTER, 0x04, "RamStart", null);
        s.add(POINTER, 0x04, "RamEnd", null);
        s.add(STRING, 0x03, "SramCode", null);
        s.add(BYTE, 0x01, "Unused", null);
        s.add(POINTER, 0x04, "SramStart", null);
        s.add(POINTER, 0x04, "SramEnd", null);
        s.add(STRING, 0x44, "Notes", null);
        
        return s;
    }
    
    public byte[] getConsoleName() {
        return consoleName;
    }
    
    public byte[] getReleaseDate() {
        return releaseDate;
    }
    
    public byte[] getDomesticName() {
        return domesticName;
    }
    
    public byte[] getInternationalName() {
        return internationalName;
    }
    
    public byte[] getVersion() {
    	return version;
    }
    
    public short getChecksum() {
        return checksum;
    }
    
    public byte[] getIoSupport() {
        return ioSupport;
    }
    
    public Address getRomStart() {
        return romStart;
    }
    
    public Address getRomEnd() {
        return romEnd;
    }
    
    public Address getRamStart() {
        return ramStart;
    }
    
    public Address getRamEnd() {
        return ramEnd;
    }
    
    public byte[] getSramCode() {
        return sramCode;
    }
    
    public byte getUnused() {
    	return unused;
    }
    
    public Address getSramStart() {
        return sramStart;
    }
    
    public Address getSramEnd() {
        return sramEnd;
    }
    
    public boolean hasSRAM() {
        if (sramCode == null) {
            return false;
        }
        
        return sramCode[0] == 'R' && sramCode[1] == 'A' && sramCode[2] == 0xF8;
    }
    
    public byte[] getNotes() {
        return notes;
    }
}
