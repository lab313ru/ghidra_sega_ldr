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
import java.util.concurrent.TimeUnit;

import docking.widgets.OptionDialog;
import ghidra.app.cmd.data.CreateArrayCmd;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class SegaLoader extends AbstractLibrarySupportLoader {

	public static final String LOADER_NAME = "Sega Mega Drive / Genesis Loader";

	private VectorsTable vectors;
	private GameHeader header;
	private MarsUserHeader marsUserHeader;
	private SegmentOptions segmentOptions;

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();

		BinaryReader reader = new BinaryReader(provider, false);

		if (reader.readAsciiString(0x100, 4).equals("SEGA")) {
			loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("68000:BE:32:MC68020", "default"), true));

			if (reader.readAsciiString(0x3c0, 15).equals("MARS CHECK MODE")) {
				loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("SuperH:BE:32:SH-2", "default"), false));
			}
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program, TaskMonitor monitor, MessageLog log) throws IOException {

		monitor.setMessage(String.format("%s : Start loading", getName()));

		BinaryReader reader = new BinaryReader(provider, false);
		FlatProgramAPI fpa = new FlatProgramAPI(program, monitor);

		segmentOptions = new SegmentOptions(loadSpec, log);
		if (!segmentOptions.hasSH2MemoryMap) {
			vectors = new VectorsTable(fpa, reader);
			header = new GameHeader(reader);
		}
		if (segmentOptions.has32XSegments) {
			marsUserHeader = new MarsUserHeader(reader);
		}

		createSegments(fpa, provider, loadSpec, program, monitor, log);
		if (!segmentOptions.hasSH2MemoryMap) {
			markVectorsTable(program, fpa, log);
			markHeader(program, fpa, log);
		}
		if (segmentOptions.has32XSegments) {
			markMarsUserHeader(program, fpa, log);
		}

		monitor.setMessage(String.format("%s : Loading done", getName()));
	}

	private void createSegments(FlatProgramAPI fpa, ByteProvider provider, LoadSpec loadSpec, Program program, TaskMonitor monitor, MessageLog log) throws IOException {
		InputStream romStream = provider.getInputStream(0);

		if (!segmentOptions.hasSH2MemoryMap) {
			createSegment(fpa, romStream, "ROM", 0x000000L, Math.min(romStream.available(), 0x3FFFFFL), true, false, true, false,
					log);
		}

		if (segmentOptions.hasSegaCDSegments) {
			if (romStream.available() > 0x3FFFFFL) {
				createSegment(fpa, provider.getInputStream(0x400000L), "EPA", 0x400000L, 0x400000L, true, true, false, false,
						log);
			} else {
				createSegment(fpa, null, "EPA", 0x400000L, 0x400000L, true, true, false, false, log);
			}
		}

		if (segmentOptions.has32XSegments) {
			createSegment(fpa, null, "32X_PRIV", 0x800000L, 0x40000L, true, true, false, false, log);
			createSegment(fpa, null, "32X_DRAM", 0x840000L, 0x20000L, true, true, false, false, log);
			createSegment(fpa, null, "32X_OWIMG", 0x860000L, 0x20000L, true, true, false, false, log);

			createSegment(fpa, provider.getInputStream(0), "32X_ROM_FIXED", 0x880000L, 0x80000L, true, true, true, false, log);
			long bank_size = 0x100000L;
			long bank_offset = 0x900000L;
			for (int i = 0; i < 4; i++) {
				createSegment(fpa, provider.getInputStream(Math.min(romStream.available(), bank_size * i)),
						"32X_ROM_BANK" + i, bank_offset, bank_size, true, true, true, false, true, log);
				if (romStream.available() < bank_size * (i + 1)) {
					break;
				}
			}

			createSegment(fpa, null, "32X_ID", 0xA130ECL, 0x4L, true, true, false, false, log);
			createNamedData(fpa, program, 0xA130ECL, "IO_32X_ID", DWordDataType.dataType, log);

			createSegment(fpa, null, "32X_BANK_SET_REG", 0xA130F1L, 0xFL, true, true, false, false, log);
			createNamedArray(fpa, program, 0xA130F1L, "IO_32X_BANK_SET_REG", 0xF, WordDataType.dataType, log);

			createSegment(fpa, null, "32X_SYS_REG", 0xA15100L, 0x80L, true, true, false, false, log);
			createNamedData(fpa, program, 0xA15100L, "IO_32X_VDP_CTRL", ByteDataType.dataType, log);
			createNamedData(fpa, program, 0xA15101L, "IO_32X_ADAPTER_CTRL", ByteDataType.dataType, log);
			createNamedData(fpa, program, 0xA15102L, "IO_32X_SH2_INT_CTRL", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15104L, "IO_32X_BANK_CTRL", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15106L, "IO_32X_DREQ_CTRL", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15108L, "IO_32X_68K_SH2_DREQ_SRC", DWordDataType.dataType, log);
			createNamedData(fpa, program, 0xA1510cL, "IO_32X_68K_SH2_DREQ_DEST", DWordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15110L, "IO_32X_68K_SH2_DREQ_LEN", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15112L, "IO_32X_68K_SH2_DREQ_FIFO", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA1511bL, "IO_32X_SEGA_TV_REG", ByteDataType.dataType, log);
			createNamedArray(fpa, program, 0xA15120L, "IO_32X_COMM", 0x10, ByteDataType.dataType, log);
			createNamedData(fpa, program, 0xA15130L, "IO_32X_PWM_CTRL", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15132L, "IO_32X_CYCLE_REG", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15134L, "IO_32X_L_CH_PULSE_REG", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15136L, "IO_32X_R_CH_PULSE_REG", WordDataType.dataType, log);
			createNamedData(fpa, program, 0xA15138L, "IO_32X_MONO_PULSE_REG", WordDataType.dataType, log);

			createSegment(fpa, null, "32X_VDP_REG", 0xA15180L, 0x80L, true, true, false, false, log);
			createNamedArray(fpa, program, 0xA15180L, "IO_32X_VDP_REG", 0x80, ByteDataType.dataType, log);

			createSegment(fpa, null, "32X_PAL", 0xA15200L, 0x200L, true, true, false, false, log);
			createNamedArray(fpa, program, 0xA15200L, "IO_32X_PAL", 0x100, WordDataType.dataType, log);

			if (segmentOptions.hasSH2MemoryMap) {
				// SH-2 Cache
				createSegment(fpa, null, "SH2_BOOT_ROM", 0x00000000L, 0x4000L, true, false, true, false, log);

				createSegment(fpa, null, "SH2_SYS_REG", 0x00004000L, 0x100L, true, true, false, false, log);
				createNamedData(fpa, program, 0x00004000L, "IO_SH2_ADAPTER_CTRL", ByteDataType.dataType, log);
				createNamedData(fpa, program, 0x00004001L, "IO_SH2_INT_CTRL", ByteDataType.dataType, log);
				createNamedData(fpa, program, 0x00004002L, "IO_SH2_STANDBY", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004005L, "IO_SH2_H_COUNT_REG", ByteDataType.dataType, log);
				createNamedData(fpa, program, 0x00004006L, "IO_SH2_DREQ_CTRL", ByteDataType.dataType, log);
				createNamedData(fpa, program, 0x00004008L, "IO_SH2_DREQ_SRC", DWordDataType.dataType, log);
				createNamedData(fpa, program, 0x0000400cL, "IO_SH2_DREQ_DEST", DWordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004010L, "IO_SH2_DREQ_LEN", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004012L, "IO_SH2_DREQ_FIFO", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004014L, "IO_SH2_VRES_INT_CLEAR", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004016L, "IO_SH2_V_INT_CLEAR", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004018L, "IO_SH2_H_INT_CLEAR", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x0000401aL, "IO_SH2_CMD_INT_CLEAR", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x0000401cL, "IO_SH2_PWM_INT_CLEAR", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x0000401eL, "IO_SH2_UNUSED", WordDataType.dataType, log);
				createNamedArray(fpa, program, 0x00004020L, "IO_SH2_COMM", 0x10, ByteDataType.dataType, log);
				createNamedData(fpa, program, 0x00004030L, "IO_32X_TIMER_CTRL", ByteDataType.dataType, log);
				createNamedData(fpa, program, 0x00004031L, "IO_32X_PWM_CTRL", ByteDataType.dataType, log);
				createNamedData(fpa, program, 0x00004032L, "IO_32X_CYCLE_REG", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004034L, "IO_32X_L_CH_PULSE_REG", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004036L, "IO_32X_R_CH_PULSE_REG", WordDataType.dataType, log);
				createNamedData(fpa, program, 0x00004038L, "IO_32X_MONO_PULSE_REG", WordDataType.dataType, log);

				createSegment(fpa, null, "SH2_VDP_REG", 0x00004100L, 0x100L, true, true, false, false, log);
				createSegment(fpa, null, "SH2_PAL", 0x00004200L, 0x200L, true, true, false, false, log);
				createSegment(fpa, provider.getInputStream(0), "SH2_ROM", 0x02000000L, 0x400000L, true, false, true, false, log);
				createSegment(fpa, null, "SH2_DRAM", 0x04000000L, 0x20000L, true, true, false, false, log);
				createSegment(fpa, null, "SH2_OWIMG", 0x04020000L, 0x20000L, true, true, false, false, log);
				createSegment(fpa, provider.getInputStream(marsUserHeader.getSourceAddress()), "SH2_SDRAM", 0x06000000L, 0x40000L, true, true, true, false, log);

				// SH-2 Cache through
				createMirrorSegment(program.getMemory(), fpa, "SH2_CT_BOOT_ROM", 0x00000000L, 0x20000000L, 0x4000L, log);
				createMirrorSegment(program.getMemory(), fpa, "SH2_CT_SYS_REG", 0x00004000L, 0x20004000L, 0x100L, log);
				createMirrorSegment(program.getMemory(), fpa, "SH2_CT_VDP_REG", 0x00004100L, 0x20004100L, 0x100L, log);
				createMirrorSegment(program.getMemory(), fpa, "SH2_CT_PAL", 0x00004200L, 0x20004200L, 0x200L, log);
				createSegment(fpa, provider.getInputStream(0), "SH2_CT_ROM", 0x22000000L, 0x400000L, true, false, true, false, log);
				createMirrorSegment(program.getMemory(), fpa, "SH2_CT_DRAM", 0x04000000L, 0x24000000L, 0x20000L, log);
				createMirrorSegment(program.getMemory(), fpa, "SH2_CT_OWIMG", 0x04020000L, 0x24020000L, 0x20000L, log);
				createMirrorSegment(program.getMemory(), fpa, "SH2_CT_SDRAM", 0x06000000L, 0x26000000L, 0x40000L, log);

				createFunction(fpa, program, monitor, marsUserHeader.getSh2MasterStartAddress(), "SHM_entry");
				createFunction(fpa, program, monitor, marsUserHeader.getSh2SlaveStartAddress(), "SHS_entry");
			} else {
				// Jump table after Game Header
				AddressSet set = new AddressSet(fpa.toAddr(0x200), fpa.toAddr(0x3c0));
				Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
				while (!set.isEmpty()) {
					AddressSet disassembleAddrs = dis.disassemble(set.getMinAddress(), set, true);
					if (disassembleAddrs.isEmpty()) {
						try {
							program.getBookmarkManager().removeBookmarks(set, BookmarkType.ERROR, Disassembler.ERROR_BOOKMARK_CATEGORY, monitor);
						} catch (CancelledException e) {
							log.appendException(e);
						}
						break;
					}
					AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembleAddrs);
					set.delete(disassembleAddrs);
				}
			}
		}

		createSegment(fpa, null, "Z80", 0xA00000L, 0x10000L, true, true, false, false, log);
		createNamedData(fpa, program, 0xA04000L, "Z80_YM2612", DWordDataType.dataType, log);

		createSegment(fpa, null, "SYS1", 0xA10000L, 16 * 2, true, true, false, true, log);
		createNamedData(fpa, program, 0xA10000L, "IO_PCBVER", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10002L, "IO_CT1_DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10004L, "IO_CT2_DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10006L, "IO_EXT_DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10008L, "IO_CT1_CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1000AL, "IO_CT2_CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1000CL, "IO_EXT_CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1000EL, "IO_CT1_RX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10010L, "IO_CT1_TX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10012L, "IO_CT1_SMODE", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10014L, "IO_CT2_RX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10016L, "IO_CT2_TX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA10018L, "IO_CT2_SMODE", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1001AL, "IO_EXT_RX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1001CL, "IO_EXT_TX", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xA1001EL, "IO_EXT_SMODE", WordDataType.dataType, log);

		createSegment(fpa, null, "SYS2", 0xA11000L, 2, true, true, false, true, log);
		createNamedData(fpa, program, 0xA11000L, "IO_RAMMODE", WordDataType.dataType, log);

		createSegment(fpa, null, "Z802", 0xA11100L, 2, true, true, false, true, log);
		createNamedData(fpa, program, 0xA11100L, "IO_Z80BUS", WordDataType.dataType, log);

		createSegment(fpa, null, "Z803", 0xA11200L, 2, true, true, false, true, log);
		createNamedData(fpa, program, 0xA11200L, "IO_Z80RES", WordDataType.dataType, log);

		createSegment(fpa, null, "FDC", 0xA12000L, 0x100, true, true, false, true, log);
		createNamedArray(fpa, program, 0xA12000L, "IO_FDC", 0x100, ByteDataType.dataType, log);

		// Leave last bytes for 32X bank register and 32X ID
		int timeSegmentSize = segmentOptions.has32XSegments ? 0xEC : 0x100;
		createSegment(fpa, null, "TIME", 0xA13000L, timeSegmentSize, true, true, false, true, log);
		createNamedArray(fpa, program, 0xA13000L, "IO_TIME", timeSegmentSize, ByteDataType.dataType, log);

		createSegment(fpa, null, "TMSS", 0xA14000L, 4, true, true, false, true, log);
		createNamedData(fpa, program, 0xA14000L, "IO_TMSS", DWordDataType.dataType, log);

		createSegment(fpa, null, "VDP", 0xC00000L, 2 * 9, true, true, false, true, log);
		createNamedData(fpa, program, 0xC00000L, "VDP_DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00002L, "VDP__DATA", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00004L, "VDP_CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00006L, "VDP__CTRL", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00008L, "VDP_CNTR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC0000AL, "VDP__CNTR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC0000CL, "VDP___CNTR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC0000EL, "VDP____CNTR", WordDataType.dataType, log);
		createNamedData(fpa, program, 0xC00011L, "VDP_PSG", ByteDataType.dataType, log);

		createSegment(fpa, null, "RAM", 0xFF0000L, 0x10000L, true, true, true, false, log);
		createMirrorSegment(program.getMemory(), fpa, "RAM", 0xFF0000L, 0xFFFF0000L, 0x10000L, log);
	}

	private void createFunction(FlatProgramAPI fpa, Program program, TaskMonitor monitor, long offset, String name) {
		Address address = fpa.toAddr(offset);
		fpa.createFunction(address, name);
		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		AddressSet disassembleAddrs = dis.disassemble(address, null);
		AutoAnalysisManager.getAnalysisManager(program).codeDefined(disassembleAddrs);
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

	private void markMarsUserHeader(Program program, FlatProgramAPI fpa, MessageLog log) {
		try {
			DataUtilities.createData(program, fpa.toAddr(0x3c0 + (segmentOptions.hasSH2MemoryMap ? 0x880000 : 0)), marsUserHeader.toDataType(), -1, false,
					ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		} catch (CodeUnitInsertionException e) {
			log.appendException(e);
		}
	}

	private void createNamedArray(FlatProgramAPI fpa, Program program, long address, String name, int numElements, DataType type, MessageLog log) {
		try {
			CreateArrayCmd arrayCmd = new CreateArrayCmd(fpa.toAddr(address), numElements, type, type.getLength());
			arrayCmd.applyTo(program);
			program.getSymbolTable().createLabel(fpa.toAddr(address), name, SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private void createNamedData(FlatProgramAPI fpa, Program program, long address, String name, DataType type, MessageLog log) {
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

	private void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size,
			boolean read, boolean write, boolean execute, boolean volatil, MessageLog log) {
	    createSegment(fpa, stream, name, address, size, read, write, execute, volatil, false, log);
    }

	private void createSegment(FlatProgramAPI fpa, InputStream stream, String name, long address, long size,
			boolean read, boolean write, boolean execute, boolean volatil, boolean overlay, MessageLog log) {
		MemoryBlock block;
		try {
			block = fpa.createMemoryBlock(name, fpa.toAddr(address), stream, size, overlay);
			block.setRead(read);
			block.setWrite(write);
			block.setExecute(execute);
			block.setVolatile(volatil);
		} catch (Exception e) {
			log.appendException(e);
		}
	}

	private void createMirrorSegment(Memory memory, FlatProgramAPI fpa, String name, long base, long new_addr,
			long size, MessageLog log) {
		MemoryBlock block;
		Address baseAddress = fpa.toAddr(base);
		try {
			block = memory.createByteMappedBlock(name, fpa.toAddr(new_addr), baseAddress, size, false);

			MemoryBlock baseBlock = memory.getBlock(baseAddress);
			block.setRead(baseBlock.isRead());
			block.setWrite(baseBlock.isWrite());
			block.setExecute(baseBlock.isExecute());
			block.setVolatile(baseBlock.isVolatile());
		} catch (LockException | MemoryConflictException | AddressOverflowException | IllegalArgumentException e) {
			log.appendException(e);
		}
	}
}
