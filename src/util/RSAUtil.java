package util;

import java.math.BigInteger;

public class RSAUtil
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

	public RSAUtil()
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
		int[] input_int=new int[input_b.length];
		BigInteger[] encryption=new BigInteger[input_b.length];
		StringBuffer encryption_buffer=new StringBuffer();
		
		System.out.println("byte\t无符号byte\t加密后得数字\t加密后转为16进制");
		for(int i=0;i<input_b.length;i++)
		{
			input_int[i]=input_b[i]&0xff; //byte转为无符号整形
			BigInteger tmp=new BigInteger(input_int[i]+""); //无符号整形转为BigInteger
			encryption[i]=tmp.modPow(e,n); //加密
			String hex_str=encryption[i].toString(16).toUpperCase(); //BigInteger转为16进制
			
			//临时输出
			System.out.println(input_b[i]+"\t"+input_int[i]+"\t"+encryption[i]+"\t"+hex_str);
			encryption_buffer.append("%"+hex_str);
		}
		
		return encryption_buffer.toString();
	}
	
	public String decryption(String encryption_str, BigInteger[] privatekey,int group)
	{
		BigInteger n = privatekey[0];
		BigInteger d = privatekey[1];
		
		
		String[] Hex_str=encryption_str.substring(1).split("%");
		BigInteger[] decryption_num=new BigInteger[Hex_str.length];
		byte[] decryption_b=new byte[Hex_str.length];
		
		//System.out.println(Hex_str.length);
		for(int i=0;i<Hex_str.length;i++)
		{
			BigInteger encryption_num=new BigInteger(Hex_str[i],16); //十六进制转为十进制
			decryption_num[i]=encryption_num.modPow(d,n); //进行解密
			decryption_b[i]=(byte)decryption_num[i].intValue(); //BigInteger先转给int再转为byte
			System.out.println(Hex_str[i]+" "+encryption_num+" "+decryption_num[i]+" "+decryption_b[i]+" ");
		
		}
		
		return new String(decryption_b);
	}
	



	

}
