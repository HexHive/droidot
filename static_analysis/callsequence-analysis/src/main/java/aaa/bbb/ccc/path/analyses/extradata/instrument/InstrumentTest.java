package aaa.bbb.ccc.path.analyses.extradata.instrument;

import aaa.bbb.ccc.StopWatch;
import aaa.bbb.ccc.Utils;
import aaa.bbb.ccc.android.AndroidProcessor;
import org.slf4j.Logger;

import java.io.File;


public class InstrumentTest {

    //public static int instrumentStatementCnt = 1;
    private static AndroidProcessor androidProcessor = new AndroidProcessor();
    public static void main(String[] args) {

        StopWatch allPhaseStopWatch = new StopWatch();
        allPhaseStopWatch.start();

        String apkFilePath = args[0];
        File apkFile = new File(apkFilePath);

        Logger logger = Utils.setupLogger(InstrumentDriver.class,apkFile.getName());
        //Options.v().set_output_format(Options.output_format_dex);

        //Options.v().set_output_format(Options.output_format_dex);
        InstrumentTestTransformer transformer = new InstrumentTestTransformer(apkFilePath);

        StopWatch singlePhaseStopWatch = new StopWatch();

        singlePhaseStopWatch.start();

        transformer.run();
        singlePhaseStopWatch.stop();
        logger.debug("path analysis time (milliseconds):" + singlePhaseStopWatch.getElapsedTime());

        allPhaseStopWatch.stop();
        logger.debug("total runtime for all phases (milliseconds):" + allPhaseStopWatch.getElapsedTime());

        logger.debug("Total number of units added to app: " + transformer.getInstrumentStmtCount());
        System.out.println("Total number of units added to app: " + transformer.getInstrumentStmtCount());
        System.out.println("Total number of intent-controlled statements: " + transformer.getIntentControlledStatementCnt());
        logger.debug("Reached end of path executor driver...");

    }
}