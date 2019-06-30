package sega;

import java.math.BigInteger;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SegaAnalyzer extends AbstractAnalyzer {

	private static final long DEF_BASE_ADDR = 0xFF8000;
	private static final String OPTION_BASE_REG = "Base Register";
	private static final String OPTION_BASE_VAL = "Base Address";
	private NegVariableBaseReg baseReg = NegVariableBaseReg.A6;
	private String baseAddr = String.format("0x%06X", DEF_BASE_ADDR); 
	
	private static boolean isSegaLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(SegaLoader.LOADER_NAME) ||
				program.getExecutableFormat().equalsIgnoreCase("Sega Genesis/MegaDrive ROM file v.2");
	}
	
	public SegaAnalyzer() {
		super("Negative Offset Variables", "Finds variables like -$XXXX(Ax) and sets specified base address", AnalyzerType.FUNCTION_ANALYZER);
	}
	
	@Override
	public boolean getDefaultEnablement(Program program) {
		return false;
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		return isSegaLoader(program);
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_BASE_REG, OptionType.ENUM_TYPE, baseReg, null, "Register which is used in -$XXXX(Ax) expressions");

		options.registerOption(OPTION_BASE_VAL, OptionType.STRING_TYPE, baseAddr, null, "Hexadecimal Base address for negative variables. 0xFF8000, for ex.");
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		super.optionsChanged(options, program);
		
		baseReg = options.getEnum(OPTION_BASE_REG, NegVariableBaseReg.A6);
		baseAddr = options.getString(OPTION_BASE_VAL, baseAddr);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Address resetAddr = null;
		
		SymbolTable symTable = program.getSymbolTable();
		List<Symbol> resets = symTable.getLabelOrFunctionSymbols(VectorsTable.VECTOR_NAMES[1], program.getGlobalNamespace());
		FunctionManager funcMgr = program.getFunctionManager();
		ProgramContext ctx = program.getProgramContext();
		Register reg = program.getRegister(baseReg.name());
		
		for (Symbol sym: resets) {
			if (sym.getSymbolType() == SymbolType.FUNCTION) {
				resetAddr = sym.getAddress();
				break;
			}
		}
		
		if (resetAddr == null) {
			return false;
		}
		
		FunctionIterator it = funcMgr.getFunctions(set, true);
		
		while (it.hasNext()) {
			Function func = it.next();

			AddressSetView as = func.getBody();

			if (as.getMinAddress().equals(resetAddr) || ctx.getRegisterValue(reg, as.getMinAddress()) != null) {
				continue;
			}
			
			RegisterValue regVal = new RegisterValue(reg, BigInteger.valueOf(Long.decode(baseAddr)));
			try {
				ctx.setRegisterValue(as.getMinAddress(), as.getMaxAddress(), regVal);
			} catch (ContextChangeException e) {
				return false;
			}
		}
		
		return true;
	}

}
