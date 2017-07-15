package util;

import java.math.BigInteger;

public class MyRSAUtil
{
	private BigInteger p;
	private BigInteger q;
	private BigInteger n;
	private BigInteger phi_n;
	private BigInteger e;
	private BigInteger d;

	private BigInteger one = new BigInteger("1");
	private BigInteger x = one;
	private BigInteger y = one;

	private BigInteger[] publickey = new BigInteger[2];
	private BigInteger[] privatekey = new BigInteger[2];

	public MyRSAUtil()
	{

	}

	public void setPQ(BigInteger p, BigInteger q)
	{
		this.p = p; // 设置质数p
		this.q = q; // 设置质数q

		System.out.println("RSA加密步骤");
		System.out.println("第一步 随机选取2个质数 p=" + p + " q=" + q);
	}

	public void rsaProcess()
	{

		n = p.multiply(q); // 获取p和q的乘积n
		System.out.println("第二步计算 n=p*q: 获得n=" + n);

		phi_n = p.subtract(one).multiply(q.subtract(one)); // 计算n的欧拉函数φ(n)
		System.out.println("第三步计算欧拉函数 φ(n)=(p-1)*(q-1): 获得φ(n)=" + phi_n);

		e = new BigInteger("65537"); // 随机选择一个整数e，条件是1< e < φ(n)
		System.out.println("第四步 随机选择一个整数e，条件是1< e < φ(n) 获得e=" + e);

		BigInteger r = gcdEx(e, phi_n);
		System.out.println("第五步 计算e对于φ(n)的模反元素d=" + this.x);
		System.out.println();

		this.d = x;

	}

	private BigInteger gcdEx(BigInteger a, BigInteger b) // 扩展欧几里得法
	{
		if (b.equals(BigInteger.ZERO))
		{
			this.x = BigInteger.ONE;
			this.y = BigInteger.ONE;
			// System.out.println("Stop ");
			return a;
		} else
		{

			BigInteger r = gcdEx(b, a.mod(b));
			// System.out.println(a + " " + b + " " + this.x + " " + this.y);
			BigInteger t = this.x;
			this.x = this.y;
			this.y = t.subtract(a.divide(b).multiply(this.y));

			return r;
		}

	}

	public BigInteger[] getMyPublicKey()
	{
		this.publickey[0] = this.n;
		this.publickey[1] = this.e;

		return publickey;
	}

	public BigInteger[] getMyPrivateKey()
	{
		this.privatekey[0] = this.n;
		this.privatekey[1] = this.d;

		return privatekey;
	}

	public String encryption(String input_string, BigInteger[] publickey,int group)
	{
		BigInteger n = publickey[0];
		BigInteger e = publickey[1];
		
		byte[] input_b=input_string.getBytes();
		
		int process_num=input_b.length+input_b.length%group;
		
		byte[] process_b=new byte[process_num];
		String[] process_b_str=new String[process_num];	
		
		
		for(int i=0;i<input_b.length;i++)
		{
			process_b[i]=input_b[i];	
		}
		
		for(int i=0;i<input_b.length%group;i++)
		{
			process_b[input_b.length+i]=32;	
		}
		
		System.out.println("字符串原始字节数组长度:"+input_b.length+" "+process_num);
		System.out.println("byte\t无符号byte\t");
		for(int i=0;i<process_num;i++)
		{
			process_b_str[i]=(process_b[i]&0xff)+"";
			
			if(process_b_str[i].length()==1)
				process_b_str[i]="00"+process_b_str[i];
			else if(process_b_str[i].length()==2)
				process_b_str[i]="0"+process_b_str[i];
					
			System.out.println(process_b[i]+"\t"+process_b_str[i]);
		}
		
		
		
		
		BigInteger[] encryption=new BigInteger[process_num/group];
		StringBuffer encryption_buffer=new StringBuffer();
		
		System.out.println("每"+group+"个字节合并为一个新的整数,对合成数字进行加密");	
		for(int i=0;i<process_num/group;i++)
		{
			String group_num_str="";
			for(int j=0;j<group;j++)
				group_num_str=group_num_str+process_b_str[i*group+j];
				
			BigInteger group_num=new BigInteger(group_num_str);
			encryption[i]=group_num.modPow(e,n); //加密
			String hex_str=encryption[i].toString(16).toUpperCase(); //BigInteger转为16进制
			
			encryption_buffer.append("%"+hex_str);
			
			System.out.println(group_num_str+"\t"+encryption[i]+"\t"+hex_str);
			
		}

	
		return encryption_buffer.toString();
	}
	
	public String decryption(String encryption_str, BigInteger[] privatekey,int group)
	{
		BigInteger n = privatekey[0];
		BigInteger d = privatekey[1];
		
		String[] Hex_str=encryption_str.substring(1).split("%");
		BigInteger[] decryption_num=new BigInteger[Hex_str.length];
		String[] decryption_num_str=new String[Hex_str.length];
		
		
		System.out.println("16进制还原成10进制数字");
		for(int i=0;i<Hex_str.length;i++)
		{
			BigInteger encryption_num=new BigInteger(Hex_str[i],16); //十六进制转为十进制
			decryption_num[i]=encryption_num.modPow(d,n); //进行解密
			decryption_num_str[i]=decryption_num[i].toString();
			
			if(decryption_num_str[i].length()%3==1)
				decryption_num_str[i]="00"+decryption_num_str[i];
			else if(decryption_num_str[i].length()%3==2)
				decryption_num_str[i]="0"+decryption_num_str[i];
			
			System.out.println(Hex_str[i]+"\t"+encryption_num+"\t"+decryption_num_str[i]);
		}
		
		
		
		
		
		
		
		System.out.println("每"+group+"一组还原无符号字节");
		int[] decryption_int=new int[Hex_str.length*group];
		byte[] decryption_b=new byte[Hex_str.length*group];
		for(int i=0;i<Hex_str.length;i++)
		{
			for(int j=0;j<group;j++)
			{	
				decryption_int[i*group+j]=Integer.parseInt(decryption_num_str[i].substring(3*j, 3*j+3));
				decryption_b[i*group+j]=(byte)decryption_int[i*group+j];
				System.out.println(decryption_int[i*group+j]+"\t"+decryption_b[i*group+j]);
				
				
			}
			
		}
		
//		for(int i=0;i<;i++)
//		{
//			
//			
//		}
		
//		byte[] decryption_b=new byte[Hex_str.length];
//		
//		
//		//System.out.println(Hex_str.length);
//		for(int i=0;i<Hex_str.length;i++)
//		{
//			BigInteger encryption_num=new BigInteger(Hex_str[i],16); //十六进制转为十进制
//			decryption_num[i]=encryption_num.modPow(d,n); //进行解密
//			decryption_b[i]=(byte)decryption_num[i].intValue(); //BigInteger先转给int再转为byte
//			System.out.println(Hex_str[i]+" "+encryption_num+" "+decryption_num[i]+" "+decryption_b[i]+" ");
//		
//		}
		
		return new String(decryption_b);
	}
	



	

}
