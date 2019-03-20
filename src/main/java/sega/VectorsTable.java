package sega;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class VectorsTable implements StructConverter {
	private static final int VECTORS_SIZE = 0x100;
	private static final int VECTORS_COUNT = VECTORS_SIZE / 4;
	
	private static final String[] VECTOR_NAMES = {
			"SSP", "Reset", "BusErr", "AdrErr", "InvOpCode", "DivBy0", "Check", "TrapV", "GPF", "Trace",
			"Reserv0", "Reserv1", "Reserv2", "Reserv3", "Reserv4", "BadInt", "Reserv10", "Reserv11",
			"Reserv12", "Reserv13", "Reserv14", "Reserv15", "Reserv16", "Reserv17", "BadIRQ", "IRQ1",
			"EXT", "IRQ3", "HBLANK", "IRQ5", "VBLANK", "IRQ7", "Trap0", "Trap1", "Trap2", "Trap3", "Trap4",
			"Trap5", "Trap6", "Trap7", "Trap8", "Trap9", "Trap10", "Trap11", "Trap12", "Trap13","Trap14",
			"Trap15", "Reserv30", "Reserv31", "Reserv32", "Reserv33", "Reserv34", "Reserv35", "Reserv36",
			"Reserv37", "Reserv38", "Reserv39", "Reserv3A", "Reserv3B", "Reserv3C", "Reserv3D", "Reserv3E",
			"Reserv3F"
	};
	
	private VectorFunc[] vectors;
	
	public VectorsTable(FlatProgramAPI fpa, BinaryReader reader) throws IOException {
		if (reader.length() < VECTORS_COUNT) {
			return;
		}
		
		reader.setPointerIndex(0);
		vectors = new VectorFunc[VECTORS_COUNT];
		
		for (int i = 0; i < VECTORS_COUNT; ++i) {
			vectors[i] = new VectorFunc(fpa.toAddr(reader.readNextUnsignedInt()), VECTOR_NAMES[i]);
		}
	}
	
	@Override
	public DataType toDataType() {
		Structure s = new StructureDataType("VectorsTable", 0);
		
		for (int i = 0; i < VECTORS_COUNT; ++i) {
			s.add(POINTER, 4, VECTOR_NAMES[i], null);
		}
		
		return s;
	}
	
	public VectorFunc[] getVectors() {
		return vectors;
	}
	
	public VectorFunc getSSP() {
	    if (vectors.length < 1) {
	        return null;
	    }
	    return vectors[0];
	}


	public VectorFunc getReset() {
	    if (vectors.length < 2) {
	        return null;
	    }
	    return vectors[1];
	}


	public VectorFunc getBusErr() {
	    if (vectors.length < 3) {
	        return null;
	    }
	    return vectors[2];
	}


	public VectorFunc getAdrErr() {
	    if (vectors.length < 4) {
	        return null;
	    }
	    return vectors[3];
	}


	public VectorFunc getInvOpCode() {
	    if (vectors.length < 5) {
	        return null;
	    }
	    return vectors[4];
	}


	public VectorFunc getDivBy0() {
	    if (vectors.length < 6) {
	        return null;
	    }
	    return vectors[5];
	}


	public VectorFunc getCheck() {
	    if (vectors.length < 7) {
	        return null;
	    }
	    return vectors[6];
	}


	public VectorFunc getTrapV() {
	    if (vectors.length < 8) {
	        return null;
	    }
	    return vectors[7];
	}


	public VectorFunc getGPF() {
	    if (vectors.length < 9) {
	        return null;
	    }
	    return vectors[8];
	}


	public VectorFunc getTrace() {
	    if (vectors.length < 10) {
	        return null;
	    }
	    return vectors[9];
	}


	public VectorFunc getReserv0() {
	    if (vectors.length < 11) {
	        return null;
	    }
	    return vectors[10];
	}


	public VectorFunc getReserv1() {
	    if (vectors.length < 12) {
	        return null;
	    }
	    return vectors[11];
	}


	public VectorFunc getReserv2() {
	    if (vectors.length < 13) {
	        return null;
	    }
	    return vectors[12];
	}


	public VectorFunc getReserv3() {
	    if (vectors.length < 14) {
	        return null;
	    }
	    return vectors[13];
	}


	public VectorFunc getReserv4() {
	    if (vectors.length < 15) {
	        return null;
	    }
	    return vectors[14];
	}


	public VectorFunc getBadInt() {
	    if (vectors.length < 16) {
	        return null;
	    }
	    return vectors[15];
	}


	public VectorFunc getReserv10() {
	    if (vectors.length < 17) {
	        return null;
	    }
	    return vectors[16];
	}


	public VectorFunc getReserv11() {
	    if (vectors.length < 18) {
	        return null;
	    }
	    return vectors[17];
	}


	public VectorFunc getReserv12() {
	    if (vectors.length < 19) {
	        return null;
	    }
	    return vectors[18];
	}


	public VectorFunc getReserv13() {
	    if (vectors.length < 20) {
	        return null;
	    }
	    return vectors[19];
	}


	public VectorFunc getReserv14() {
	    if (vectors.length < 21) {
	        return null;
	    }
	    return vectors[20];
	}


	public VectorFunc getReserv15() {
	    if (vectors.length < 22) {
	        return null;
	    }
	    return vectors[21];
	}


	public VectorFunc getReserv16() {
	    if (vectors.length < 23) {
	        return null;
	    }
	    return vectors[22];
	}


	public VectorFunc getReserv17() {
	    if (vectors.length < 24) {
	        return null;
	    }
	    return vectors[23];
	}


	public VectorFunc getBadIRQ() {
	    if (vectors.length < 25) {
	        return null;
	    }
	    return vectors[24];
	}


	public VectorFunc getIRQ1() {
	    if (vectors.length < 26) {
	        return null;
	    }
	    return vectors[25];
	}


	public VectorFunc getEXT() {
	    if (vectors.length < 27) {
	        return null;
	    }
	    return vectors[26];
	}


	public VectorFunc getIRQ3() {
	    if (vectors.length < 28) {
	        return null;
	    }
	    return vectors[27];
	}


	public VectorFunc getHBLANK() {
	    if (vectors.length < 29) {
	        return null;
	    }
	    return vectors[28];
	}


	public VectorFunc getIRQ5() {
	    if (vectors.length < 30) {
	        return null;
	    }
	    return vectors[29];
	}


	public VectorFunc getVBLANK() {
	    if (vectors.length < 31) {
	        return null;
	    }
	    return vectors[30];
	}


	public VectorFunc getIRQ7() {
	    if (vectors.length < 32) {
	        return null;
	    }
	    return vectors[31];
	}


	public VectorFunc getTrap0() {
	    if (vectors.length < 33) {
	        return null;
	    }
	    return vectors[32];
	}


	public VectorFunc getTrap1() {
	    if (vectors.length < 34) {
	        return null;
	    }
	    return vectors[33];
	}


	public VectorFunc getTrap2() {
	    if (vectors.length < 35) {
	        return null;
	    }
	    return vectors[34];
	}


	public VectorFunc getTrap3() {
	    if (vectors.length < 36) {
	        return null;
	    }
	    return vectors[35];
	}


	public VectorFunc getTrap4() {
	    if (vectors.length < 37) {
	        return null;
	    }
	    return vectors[36];
	}


	public VectorFunc getTrap5() {
	    if (vectors.length < 38) {
	        return null;
	    }
	    return vectors[37];
	}


	public VectorFunc getTrap6() {
	    if (vectors.length < 39) {
	        return null;
	    }
	    return vectors[38];
	}


	public VectorFunc getTrap7() {
	    if (vectors.length < 40) {
	        return null;
	    }
	    return vectors[39];
	}


	public VectorFunc getTrap8() {
	    if (vectors.length < 41) {
	        return null;
	    }
	    return vectors[40];
	}


	public VectorFunc getTrap9() {
	    if (vectors.length < 42) {
	        return null;
	    }
	    return vectors[41];
	}


	public VectorFunc getTrap10() {
	    if (vectors.length < 43) {
	        return null;
	    }
	    return vectors[42];
	}


	public VectorFunc getTrap11() {
	    if (vectors.length < 44) {
	        return null;
	    }
	    return vectors[43];
	}


	public VectorFunc getTrap12() {
	    if (vectors.length < 45) {
	        return null;
	    }
	    return vectors[44];
	}


	public VectorFunc getTrap13() {
	    if (vectors.length < 46) {
	        return null;
	    }
	    return vectors[45];
	}


	public VectorFunc getTrap14() {
	    if (vectors.length < 47) {
	        return null;
	    }
	    return vectors[46];
	}


	public VectorFunc getTrap15() {
	    if (vectors.length < 48) {
	        return null;
	    }
	    return vectors[47];
	}


	public VectorFunc getReserv30() {
	    if (vectors.length < 49) {
	        return null;
	    }
	    return vectors[48];
	}


	public VectorFunc getReserv31() {
	    if (vectors.length < 50) {
	        return null;
	    }
	    return vectors[49];
	}


	public VectorFunc getReserv32() {
	    if (vectors.length < 51) {
	        return null;
	    }
	    return vectors[50];
	}


	public VectorFunc getReserv33() {
	    if (vectors.length < 52) {
	        return null;
	    }
	    return vectors[51];
	}


	public VectorFunc getReserv34() {
	    if (vectors.length < 53) {
	        return null;
	    }
	    return vectors[52];
	}


	public VectorFunc getReserv35() {
	    if (vectors.length < 54) {
	        return null;
	    }
	    return vectors[53];
	}


	public VectorFunc getReserv36() {
	    if (vectors.length < 55) {
	        return null;
	    }
	    return vectors[54];
	}


	public VectorFunc getReserv37() {
	    if (vectors.length < 56) {
	        return null;
	    }
	    return vectors[55];
	}


	public VectorFunc getReserv38() {
	    if (vectors.length < 57) {
	        return null;
	    }
	    return vectors[56];
	}


	public VectorFunc getReserv39() {
	    if (vectors.length < 58) {
	        return null;
	    }
	    return vectors[57];
	}


	public VectorFunc getReserv3A() {
	    if (vectors.length < 59) {
	        return null;
	    }
	    return vectors[58];
	}


	public VectorFunc getReserv3B() {
	    if (vectors.length < 60) {
	        return null;
	    }
	    return vectors[59];
	}


	public VectorFunc getReserv3C() {
	    if (vectors.length < 61) {
	        return null;
	    }
	    return vectors[60];
	}


	public VectorFunc getReserv3D() {
	    if (vectors.length < 62) {
	        return null;
	    }
	    return vectors[61];
	}


	public VectorFunc getReserv3E() {
	    if (vectors.length < 63) {
	        return null;
	    }
	    return vectors[62];
	}


	public VectorFunc getReserv3F() {
	    if (vectors.length < 64) {
	        return null;
	    }
	    return vectors[63];
	}
}
