import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class analyse {
	
	// List of file types that are to be excluded from analysis
	private static final Set<String> excludedTypes = new HashSet<String>(Arrays.asList(
		     new String[] {"png","jpeg","jpg"}
		));
	
	// pattern for finding IP and email in the code
	private static String ipPat =      
			"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

	private static String emailPat = 
			"^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
	
	//It could be used to execute unwanted JavaScript in a client's browser
	private static String escapeXmlpat = "escapeXml=\"false\"";
	
	// File write in 'MODE_WORLD_READABLE' mode
	private static String fileReadMode = "MODE_WORLD_READABLE";
	
	// All Strings/patterns that can interesting for analysis
	private static String[] patterns = {"sql","dbconnect","dbname","pwlist","username",
			"pass","passwd","pwd","user",emailPat,ipPat,escapeXmlpat,fileReadMode};
	
	
	public static void main(String[] args)
	{
			if(args.length < 2)
			{
				System.out.println("Useage: java analyse.java <folder-path> <ouput-folder>");
				System.exit(0);
			}		
			System.out.println("Analysing...");
			String path = args[0];
			List<File> files = getAllFiles(path);
			
			String outputFile = args[1]+"analysis-report.txt";
			
			// List of all patterns
			List<Pattern> patternList = storePatterns();
			
			/*
			 * System.out.println("## File List:::");
			for(File f : files)
				System.out.println(f.getName());
			*/
			
			findAndPrint(files,patternList,outputFile);
			System.out.println("Done");
	}

	private static void findAndPrint(List<File> files, List<Pattern> patternList,String outputFile)
	{
		try
		{
			System.out.println("Saving report in:"+new File(outputFile).getAbsolutePath());
			BufferedWriter bw = new BufferedWriter(new FileWriter(outputFile,false));
			for(File file : files)
			{
				BufferedReader br = new BufferedReader(new FileReader(file));
				String line = br.readLine();
				int lineNumber = 0;
				while(line != null)
				{
					lineNumber++;
					for(Pattern pat : patternList)
					{
						   Matcher m = pat.matcher(line);
						   if (m.find())
						   {
							   bw.append("## File Name:"+file.getAbsolutePath());
							   bw.newLine();
							   bw.append("# Suspecius line(line Number:"+lineNumber+"):");
							   bw.newLine();
							   bw.append(line);
							   bw.newLine();
							   bw.newLine();
						   }
					}
					line = br.readLine();
				}
				br.close();
			}			
			bw.close();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}

	private static List<Pattern> storePatterns() 
	{
		List<Pattern> patternList = new ArrayList<Pattern>();
		
		for(String pat : patterns)
		{
			 Pattern p = Pattern.compile(pat);
			 patternList.add(p);
		}
		
		return patternList;
	}

	private static List<File> getAllFiles(String path) 
	{
		List<File> files = new ArrayList<File>();
		iterateDir(path,files);
		
		return files;
	}

	private static void iterateDir(String path, List<File> files)
	{
		File root = new File( path );
        File[] list = root.listFiles();

        if (list == null) 
        	return;

        for ( File f : list )
        {
            if ( f.isDirectory() )
            {
                iterateDir(f.getAbsolutePath(),files);
            }
            else
            {
                //System.out.println( "File:" + f.getAbsoluteFile());   
                String[] ext = f.getName().split("\\.");
                String fileType = ext[ext.length-1];
           /*
            *   Ignore all files of types that are in ecludedType list
            *   Add rest in files list   
            */                 
                if(!excludedTypes.contains(fileType))
                	files.add(f.getAbsoluteFile());
            }
        }	
	}	
}
