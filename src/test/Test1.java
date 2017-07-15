package test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import util.MyRSAUtil;

public class Test1
{ 
	
	public static void main(String[] args)
	{
		
		
		 MyRSAUtil rsa = new MyRSAUtil();
		// rsa.setPQ(new BigInteger("701"), new BigInteger("709"));
		 rsa.setPQ(new BigInteger("33478071698956898786044169848212690817704794983713768568912431388982883793878002287614711652531743087737814467999489"), new BigInteger("36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917"));
		 rsa.rsaProcess();
		 BigInteger[] publickey = rsa.getMyPublicKey();
		 BigInteger[] privatekey = rsa.getMyPrivateKey();
		 
		 
		
		
		 
		 
		 
		 
		 
		 
		 
		 String s="  ";
		 byte[] bs=s.getBytes();
		 String s1=(bs[0]&0xff)+"";
		 System.out.println(s1);
		 
		 
		 System.out.println("公钥:" + publickey[0] + " " + publickey[1]);
		 System.out.println("私钥:" + privatekey[0] + " " + privatekey[1]);
		 System.out.println();
		 
		 String message = "你们不要老想弄个大新闻";
		 System.out.println("需要加密的內容:" + message);
		 String encryption_str = rsa.encryption(message, publickey,6);

		 System.out.println();
		 
		 System.out.println("密文:" + encryption_str);
		 String decryption_str = rsa.decryption(encryption_str, privatekey,6);
		 System.out.println("明文:" + decryption_str);

		

		
	}
}
