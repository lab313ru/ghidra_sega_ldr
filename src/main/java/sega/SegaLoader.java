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
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
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
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
			MemoryConflictHandler handler, TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {

		monitor.setMessage(String.format("%s : Start loading", getName()));

		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		vectors = new VectorsTable(fpa, reader);
		header = new GameHeader(reader);

		createSegments(fpa, provider, program, monitor, log);
		markVectorsTable(program, fpa, log);
		markHeader(program, fpa, log);

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options) {

		// TODO: If this loader has custom options, validate them here. Not all options
		// require
		// validation.

		return super.validateOptions(provider, loadSpec, options);
	}

	private void createSegments(FlatProgramAPI fpa, ByteProvider provider, Program program, TaskMonitor monitor,
			MessageLog log) throws IOException {
		InputStream romStream = provider.getInputStream(0);

		createSegment(fpa, romStream, "ROM", 0x000000L, Math.min(romStream.available(), 0x3FFFFFL), true, false, true,
				log);

		if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Question",
				"Create Sega CD segment?")) {
			if (romStream.available() > 0x3FFFFFL) {
				createSegment(fpa, provider.getInputStream(0x400000L), "EPA", 0x400000L, 0x400000L, true, true, false,
						log);
			} else {
				createSegment(fpa, null, "EPA", 0x400000L, 0x400000L, true, true, false, log);
			}
		}

		if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Question",
				"Create Sega 32X segment?")) {
			createSegment(fpa, null, "32X", 0x800000L, 0x200000L, true, true, false, log);
		}

		createSegment(fpa, null, "Z80", 0xA00000L, 0x10000L, true, true, false, log);
		createNamedArray(fpa, program, 0xA04000L, "Z80_YM2612", 1, DWordDataType.dataType, log);

		createSegment(fpa, null, "SYS1", 0xA10000L, 16 * 2, true, true, false, log);
		createNamedArray(fpa, program, 0xA10000L, "IO_PCBVER", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10002L, "IO_CT1_DATA", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10004L, "IO_CT2_DATA", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10006L, "IO_EXT_DATA", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10008L, "IO_CT1_CTRL", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA1000AL, "IO_CT2_CTRL", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA1000CL, "IO_EXT_CTRL", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA1000EL, "IO_CT1_RX", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10010L, "IO_CT1_TX", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10012L, "IO_CT1_SMODE", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10014L, "IO_CT2_RX", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10016L, "IO_CT2_TX", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA10018L, "IO_CT2_SMODE", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA1001AL, "IO_EXT_RX", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA1001CL, "IO_EXT_TX", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xA1001EL, "IO_EXT_SMODE", 1, WordDataType.dataType, log);

		createSegment(fpa, null, "SYS2", 0xA11000L, 2, true, true, false, log);
		createNamedArray(fpa, program, 0xA11000L, "IO_RAMMODE", 1, WordDataType.dataType, log);

		createSegment(fpa, null, "Z802", 0xA11100L, 2, true, true, false, log);
		createNamedArray(fpa, program, 0xA11100L, "IO_Z80BUS", 1, WordDataType.dataType, log);

		createSegment(fpa, null, "Z803", 0xA11200L, 2, true, true, false, log);
		createNamedArray(fpa, program, 0xA11200L, "IO_Z80RES", 1, WordDataType.dataType, log);

		createSegment(fpa, null, "FDC", 0xA12000L, 0x100, true, true, false, log);
		createNamedArray(fpa, program, 0xA12000L, "IO_FDC", 0x100, ByteDataType.dataType, log);

		createSegment(fpa, null, "TIME", 0xA13000L, 0x100, true, true, false, log);
		createNamedArray(fpa, program, 0xA13000L, "IO_TIME", 0x100, ByteDataType.dataType, log);

		createSegment(fpa, null, "TMSS", 0xA14000L, 4, true, true, false, log);
		createNamedArray(fpa, program, 0xA14000L, "IO_TMSS", 1, DWordDataType.dataType, log);

		createSegment(fpa, null, "VDP", 0xC00000L, 2 * 9, true, true, false, log);
		createNamedArray(fpa, program, 0xC00000L, "VDP_DATA", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xC00002L, "VDP__DATA", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xC00004L, "VDP_CTRL", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xC00006L, "VDP__CTRL", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xC00008L, "VDP_CNTR", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xC0000AL, "VDP__CNTR", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xC0000CL, "VDP___CNTR", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xC0000EL, "VDP____CNTR", 1, WordDataType.dataType, log);
		createNamedArray(fpa, program, 0xC00011L, "VDP_PSG", 1, ByteDataType.dataType, log);

		createSegment(fpa, null, "RAM", 0xFF0000L, 0x10000L, true, true, true, log);
		createMirrorSegment(program.getMemory(), fpa, "RAM", 0xFF0000L, 0xFFFF0000L, 0x10000L, log);

		if (header.hasSRAM()) {
			long sramStart = header.getSramStart();
			long sramEnd = header.getSramEnd();

			if (sramStart >= 0x200000L && sramEnd <= 0x20FFFFL && sramStart < sramEnd) {
				createSegment(fpa, null, "SRAM", sramStart, sramEnd - sramStart + 1, true, true, false, log);
			}
		}
	}

	private void markVectorsTable(Program program, FlatProgramAPI fpa, MessageLog log) {
		try {
			DataUtilities.createData(program, fpa.toAddr(0), vectors.toDataType(), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

			for (VectorFunc func : vectors.getVectors()) {
				fpa.createFunction(func.getAddress(), func.getName());
			}
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}

	private void markHeader(Program program, FlatProgramAPI fpa, MessageLog log) {
		try {
			DataUtilities.createData(program, fpa.toAddr(0x100), header.toDataType(), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}

	private void createNamedArray(FlatProgramAPI fpa, Program program, long address, String name, int numElements,
			DataType type, MessageLog log) {
		if (numElements > 1) {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type,
					ByteDataType.dataType.getLength());
			arrayCmd.applyTo(program);
		} else {
			try {
				if (type.equals(ByteDataType.dataType)) {
					fpa.createByte(fpa.toAddr(address));
				} else if (type.equals(WordDataType.dataType)) {
					fpa.createWord(fpa.toAddr(address));
				} else if (type.equals(DWordDataType.dataType)) {
					fpa.createDWord(fpa.toAddr(address));
				}
				program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
			} catch (Exception e) {
				log.appendException(e);
			}
		}
	}

	private void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size,
			boolean read, boolean write, boolean execute, MessageLog log) {
		MemoryBlock block = null;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, false);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(block.isVolatile());
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createMirrorSegment(Memory memory, FlatProgramAPI fpa, String name, long base, long new_addr,
			long size, MessageLog log) {
		MemoryBlock block = null;
		Address baseAddress = fpa.toAddr(base);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(new_addr), baseAddress, size);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead(baseBlock.isRead());
			block.setWrite(baseBlock.isWrite());
			block.setExecute(baseBlock.isExecute());
			block.setVolatile(baseBlock.isVolatile());
		} catch (LockException | MemoryConflictException | AddressOverflowException e) {
			log.appendException(e);
		}
	}
}
