# About
PEParser is a Windows application built using the MFC library. It is designed to analyze and modify Portable Executable (PE) files, similar to tools like CFF Explorer. The tool provides an intuitive user interface for exploring and editing various sections of PE files.
## Key Features
1. PE Header Analysis<br>
   Inspect and analyze the DOS Header, NT Headers, and Section Headers to understand the structure of the PE file.
2. Import Table Exploration <br>
   Display and examine entries in the Import Table, providing a clear view of DLLs and their associated functions.
3. Section Addition<br>
   Add new sections to the end of the PE file, ensuring proper alignment and integration with existing sections.
4. Import Adder <br>
  Inject custom DLLs and functions into the Import Table, enabling advanced file manipulation or redirection of function calls.
5. Address Converter<br>
  Convert between RVA, VA and File Offset
# Usage
1. Open a PE File<br>
   Select the desired PE file and click "OK" to load it.
2. View Headers<br>
   Navigate through the nodes in the left panel to inspect the DOS Header, NT Headers, and Section Headers.
![image](https://github.com/user-attachments/assets/f1486a90-91d7-4407-91e2-ff5d5cf58046)
3. Explore the Import Table<br>
   Click on "Import Directory" in the left panel. Select a module name to display its associated functions below.
   ![image](https://github.com/user-attachments/assets/8c4e6040-9fb9-4488-8463-872400a67998)
4. Add a New Section
   - Navigate to "Section Headers" in the left panel.
   - Right-click on the displayed list and choose "Add Sections."
   - Enter the section name and size in the pop-up dialog.
   ![image](https://github.com/user-attachments/assets/0cfd0b6d-af34-461f-a952-60efba6dc366)
   - The new section will appear in the list.
   ![image](https://github.com/user-attachments/assets/e2035a8c-726e-430f-94f9-13b62b5b4843)
5. Add DLLs and Functions to the Import Table
   - Navigate to "Import Directory" in the left panel.
   - Right-click on the list and select "Add Import."
   - Enter the DLL name and function name in the dialog, then click "Rebuild Import Table."
   ![image](https://github.com/user-attachments/assets/ec784210-eb41-4000-89e1-12daa165d734)
   - The new DLL and functions will be displayed in the list.
   ![image](https://github.com/user-attachments/assets/7e2f2c59-1ad5-4b3d-9bc0-d28979645f48)
6. Convert Addresses <br>
   Use the address converter by entering an address (RVA, VA, or File Offset) and pressing "Enter" to view its converted value.
   ![image](https://github.com/user-attachments/assets/9e2ccbb5-ed56-41f4-81fe-fb51a88ad02d)

   
   
