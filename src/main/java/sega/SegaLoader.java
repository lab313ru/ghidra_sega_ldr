/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sega;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import docking.widgets.OptionDialog;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MemoryConflictHandler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SegaLoader extends AbstractLibrarySupportLoader {
	
	private VectorsTable vectors;
	private GameHeader header;

	@Override
	public String getName() {
		return "Sega Mega Drive / Genesis Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		BinaryReader reader = new BinaryReader(provider, false);
		
		if (reader.readAsciiString(0x100, 4).equals(new String("SEGA"))) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:MC68020", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		monitor.setMessage(String.format("%s : Start loading", getName()));
		
		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);
		
		vectors = new VectorsTable(fpa, reader);
		header = new GameHeader(fpa, reader);
		
		createSegments(fpa, provider, program, monitor);
		markVectorsTable(program, fpa);
		markHeader(program, fpa);

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			DomainObject domainObject, boolean isLoadIntoProgram) {
		List<Option> list =
			super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		// TODO: If this loader has custom options, add them to 'list'
		list.add(new Option("Option name goes here", "Default option value goes here"));

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here.  Not all options require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}
	
	private void createSegments(FlatProgramAPI fpa, ByteProvider provider, Program program, TaskMonitor monitor) throws IOException {
		InputStream romStream = provider.getInputStream(0);
		
		createSegment(fpa, romStream, "ROM", fpa.toAddr(0x000000), Math.min(romStream.available(), 0x3FFFFF), true, false, true);
		
		if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Question", "Create Sega CD segment?")) {
			if (romStream.available() > 0x3FFFFF) {
				InputStream epaStream = provider.getInputStream(0x400000);
				
				createSegment(fpa, epaStream, "EPA", fpa.toAddr(0x400000), 0x400000, true, true, false);
			} else {
				createSegment(fpa, null, "EPA", fpa.toAddr(0x400000), 0x400000, true, true, false);
			}
		}
		
		if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Question", "Create Sega 32X segment?")) {
			createSegment(fpa, null, "32X", fpa.toAddr(0x800000), 0x200000, true, true, false);
		}
		
		createSegment(fpa, null, "Z80", fpa.toAddr(0xA00000), 0x10000, true, true, false);
		createNamedDwordArray(fpa, program, fpa.toAddr(0xA04000), "Z80_YM2612", 1);
		
		createSegment(fpa, null, "SYS1", fpa.toAddr(0xA10000), 16 * 2, true, true, false);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10000), "IO_PCBVER", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10002), "IO_CT1_DATA", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10004), "IO_CT2_DATA", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10006), "IO_EXT_DATA", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10008), "IO_CT1_CTRL", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA1000A), "IO_CT2_CTRL", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA1000C), "IO_EXT_CTRL", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA1000E), "IO_CT1_RX", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10010), "IO_CT1_TX", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10012), "IO_CT1_SMODE", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10014), "IO_CT2_RX", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10016), "IO_CT2_TX", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA10018), "IO_CT2_SMODE", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA1001A), "IO_EXT_RX", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA1001C), "IO_EXT_TX", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA1001E), "IO_EXT_SMODE", 1);
		
		createSegment(fpa, null, "SYS2", fpa.toAddr(0xA11000), 2, true, true, false);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA11000), "IO_RAMMODE", 1);
		
		createSegment(fpa, null, "Z802", fpa.toAddr(0xA11100), 2, true, true, false);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA11100), "IO_Z80BUS", 1);

		createSegment(fpa, null, "Z803", fpa.toAddr(0xA11200), 2, true, true, false);
		createNamedWordArray(fpa, program, fpa.toAddr(0xA11200), "IO_Z80RES", 1);

		createSegment(fpa, null, "FDC", fpa.toAddr(0xA12000), 0x100, true, true, false);
		createNamedByteArray(fpa, program, fpa.toAddr(0xA12000), "IO_FDC", 0x100);

		createSegment(fpa, null, "TIME", fpa.toAddr(0xA13000), 0x100, true, true, false);
		createNamedByteArray(fpa, program, fpa.toAddr(0xA13000), "IO_TIME", 0x100);

		createSegment(fpa, null, "TMSS", fpa.toAddr(0xA14000), 4, true, true, false);
		createNamedDwordArray(fpa, program, fpa.toAddr(0xA14000), "IO_TMSS", 1);

		createSegment(fpa, null, "VDP", fpa.toAddr(0xC00000), 2 * 9, true, true, false);
		createNamedWordArray(fpa, program, fpa.toAddr(0xC00000), "VDP_DATA", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xC00002), "VDP__DATA", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xC00004), "VDP_CTRL", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xC00006), "VDP__CTRL", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xC00008), "VDP_CNTR", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xC0000A), "VDP__CNTR", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xC0000C), "VDP___CNTR", 1);
		createNamedWordArray(fpa, program, fpa.toAddr(0xC0000E), "VDP____CNTR", 1);
		createNamedByteArray(fpa, program, fpa.toAddr(0xC00011), "VDP_PSG", 1);
		
		createSegment(fpa, null, "RAM", fpa.toAddr(0xFF0000), 0x10000, true, true, true);
		
		if (header.hasSRAM()) {
			Address sramStart = header.getSramStart();
			Address sramEnd = header.getSramEnd();
			
			if (sramStart.getOffset() >= 0x200000 && sramEnd.getOffset() <= 0x20FFFF && sramStart.getOffset() < sramEnd.getOffset()) {
				createSegment(fpa, null, "SRAM", sramStart, sramEnd.getOffset() - sramStart.getOffset() + 1, true, true, false);
			}
		}
	}
	
	private void markVectorsTable(Program program, FlatProgramAPI fpa) {
		try {
			DataUtilities.createData(program, fpa.toAddr(0), vectors.toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
			
			for (VectorFunc func : vectors.getVectors()) {
				fpa.createFunction(func.getAddress(), func.getName());
			}
		} catch (CodeUnitInsertionException e) {
			Msg.error(this, "Vectors mark conflict at 0x000000");
		}
	}
	
	private void markHeader(Program program, FlatProgramAPI fpa) {
		try {
			DataUtilities.createData(program, fpa.toAddr(0x100), header.toDataType(), -1, false, ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		} catch (CodeUnitInsertionException e) {
			Msg.error(this, "Vectors mark conflict at 0x000100");
		}
	}
	
	private void createNamedByteArray(FlatProgramAPI fpa, Program program, Address address, String name, int numElements) {
		if (numElements > 1) {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(address, numElements, ByteDataType.dataType, ByteDataType.dataType.getLength());
			arrayCmd.applyTo(program);
		} else {
			try {
				fpa.createByte(address);
			} catch (Exception e) {
				Msg.error(this, "Cannot create byte. " + e.getMessage());
			}
		}
		
		try {
			program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			Msg.error(this, String.format("%s : Error creating array %s", getName(), name));
		}
	}
	
	private void createNamedWordArray(FlatProgramAPI fpa, Program program, Address address, String name, int numElements) {
		if (numElements > 1) {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(address, numElements, WordDataType.dataType, WordDataType.dataType.getLength());
			arrayCmd.applyTo(program);
		} else {
			try {
				fpa.createWord(address);
			} catch (Exception e) {
				Msg.error(this, "Cannot create word. " + e.getMessage());
			}
		}
		
		try {
			program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			Msg.error(this, String.format("%s : Error creating array %s", getName(), name));
		}
	}
	
	private void createNamedDwordArray(FlatProgramAPI fpa, Program program, Address address, String name, int numElements) {
		if (numElements > 1) {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(address, numElements, DWordDataType.dataType, DWordDataType.dataType.getLength());
			arrayCmd.applyTo(program);
		} else {
			try {
				fpa.createDWord(address);
			} catch (Exception e) {
				Msg.error(this, "Cannot create dword. " + e.getMessage());
			}
		}
		
		try {
			program.getSymbolTable().createLabel(address, name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			Msg.error(this, String.format("%s : Error creating array %s", getName(), name));
		}
	}
	
	private void createSegment(FlatProgramAPI fpa, InputStream stream, String name, Address address, long size, boolean read, boolean write, boolean execute) {
		MemoryBlock block = null;
		try {
			block = fpa.createMemoryBlock(name, address, stream, size, false);
			block.setRead(read);
			block.setWrite(read);
			block.setExecute(execute);
		} catch (Exception e) {
			Msg.error(this, String.format("Error creating %s segment", name));
		}
	}
}
