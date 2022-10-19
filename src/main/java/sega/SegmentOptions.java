package sega;

import java.util.concurrent.TimeUnit;

import docking.widgets.OptionDialog;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.lang.LanguageNotFoundException;

public class SegmentOptions {
	public final boolean hasSH2MemoryMap;
	public final boolean has32XSegments;
	public final boolean hasSegaCDSegments;

	public SegmentOptions(LoadSpec loadSpec, MessageLog log) throws LanguageNotFoundException {
		String languageID = loadSpec.getLanguageCompilerSpec().getLanguage().getLanguageID().getIdAsString();
		this.hasSH2MemoryMap = languageID.contains("SuperH");
		log.appendMsg(String.format("LanguageID is %s, adding Mega Drive segments assuming 32X is %s",
				languageID,
				this.hasSH2MemoryMap ? "loaded" : "NOT loaded"));

		try {
			TimeUnit.SECONDS.sleep(1);
		} catch (InterruptedException e) {
			log.appendException(e);
		}

		this.has32XSegments = OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Question",
				"Create Sega 32X segments?");

		this.hasSegaCDSegments = OptionDialog.YES_OPTION == OptionDialog.showYesNoDialogWithNoAsDefaultButton(null, "Question",
				"Create Sega CD segment?");
	}
}
