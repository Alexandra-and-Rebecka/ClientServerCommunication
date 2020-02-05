package com.company;

import java.security.Security;

import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {
    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        String name = "BC";
	    if (Security.getProvider(name) == null) {
	        System.out.println("Not installed");
        } else {
	        System.out.println("Installed");
        }


        XSSFWorkbook workbook = new XSSFWorkbook();
        XSSFSheet sheet = workbook.createSheet("Authentication");

        Row row = sheet.createRow(0);
        Cell cell = row.createCell(0);
        cell.setCellValue("Username");
        cell = row.createCell(1);
        cell.setCellValue("Password");

    }
}
