## 安链云常用工具包
### com.zhongan.swzc.common.utils.auth ：授权认证
- ####  类 JWTUtil
JWT工具类
###### 方法详细说明：
   ```
   /**
    * JWT签名
    * @param key
   * @param id
    * @return
   */
   public String signJWT(String key, Long id) 
   
   /**
    * 验证token是否合法
    * @param token
    * @return
   */
   public boolean verifyJWT(String token)
   
   /**
   * 获取ID
    * @param token
   * @param key
    * @return
    */
   public Long getID(String token, String key)
   
   // ....
   ```
   ###### 用例参考：
   ```
    //生成token
    JWTUtil jwtUtil = new JWTUtil();
     jwtUtil.setExpire(60000L);
    jwtUtil.setIssuer("issuer");
     jwtUtil.setSecret("secret");
     String token = jwtUtil.signJWT("uid", 100L);
     System.out.println(token);
     
     //验证token
     boolean b = jwtUtil.verifyJWT(token);
     System.out.println(b);
     
     //获取token中的id值
     Long uid = jwtUtil.getID(token, "uid");
     System.out.println(uid);
   ```
  
 ---
 
### com.zhongan.swzc.common.utils.bean ：Bean工具
- ####  类 BeanUtil
Bean工具类
###### 方法详细说明：
   ```
   /**
     * 拷贝对象
     * @param source 源对象
     * @param target 目标对象
     * @param <T>
     * @return
     */
    public static <T> T copy(Object source, T target)
    
    /**
     * 拷贝对象
     * @param source 源对象
     * @param targetClass 目前对象Class
     * @param <T>
     * @return
     */
    public static <T> T copy(Object source, Class<T> targetClass)
    
    /**
     * 拷贝对象
     * @param source 源List
     * @param targetClass 目标对象
     * @param <E>
     * @return
     */
    public static <E> List<E> convert(List<?> source, Class<E> targetClass)
    
    /**
     * 将对象装换为map
     * @param bean
     * @return
     */
    public static <T> Map<String, Object> beanToMap(T bean)
   ```
 ###### 用例参考：
   ```
    RMB rmb = new RMB("人民币", 20));
    Coin coin = new Coin();
    BeanUtil.copy(rmb, coin);
    System.out.println(coin.toString());
    
    Coin coin2 = BeanUtil.copy(rmb, Coin.class);
    System.out.println(coin2.toString());
    
    Map<String, Object> map = BeanUtil.beanToMap(rmb);
    System.out.println(map.toString());
   ```
   
- ####  类 ObjectMapUtils
Object-Map工具类
###### 方法详细说明：
```
    /***
     * 将对象转换为map对象
     * @param thisObj 对象
     * @return
     */
    public static Map objectToMap(Object thisObj)
    
    /**
     * 将Map对象通过反射机制转换成Bean对象
     *
     * @param map 存放数据的map对象
     * @param clazz 待转换的class
     * @return 转换后的Bean对象
     * @throws Exception 异常
     */
    public static Object mapToObject(Map<String, Object> map, Class<?> clazz) throws Exception
    
    /**
     * javaBean 转 Map
     * @param object 需要转换的javabean
     * @return  转换结果map
     * @throws Exception
     */
    public static Map<String, Object> beanToMap(Object object) throws Exception
    
    /**
     *
     * @param map   需要转换的map
     * @param cls   目标javaBean的类对象
     * @return  目标类object
     * @throws Exception
     */
    public static Object mapToBean(Map<String, Object> map, Class cls) throws Exception
```
###### 用例参考：
```
RMB rmb = new RMB("人民币", 20);
Map map = ObjectMapUtils.objectToMap(rmb);
System.out.println(map.toString());

Object object = ObjectMapUtils.mapToObject(map, RMB.class);
RMB rmb2 = (RMB) object;
System.out.println(rmb2);

Map<String, Object> map2 = ObjectMapUtils.beanToMap(rmb);
System.out.println(map2.toString());

Object object3 = ObjectMapUtils.mapToBean(map2, RMB.class);
RMB rmb3 = (RMB) object;
System.out.println(rmb3);
```
### com.zhongan.swzc.common.utils.crypto ：安全加密
- ####  类 AES
AES工具类
###### 方法详细说明：
```
/**
 * AES加密
 * 密钥填充长度为128位
 * @param model	    加密模式
 * @param iv	    偏移量（CBC模式需要填写、最少16个字节长度；ECB模式不用填）
 * @param key		秘钥
 * @param content	要加密的内容
 * @param outformat	输出格式(HEX,BASE64)
 * @return 加密后的密文
 */
public static String encrypt(String model, String iv, String key,String content,String outformat) throws Exception

/**
 * AES解密
 * 密钥填充长度为128位
 * @param model	加密模式
 * @param iv	    偏移量,ECB模式不用填
 * @param key		秘钥
 * @param content	要解密密的内容
 * @param informat	输出格式(HEX,BASE64)
 * @return 解密出的明文
 */
public static String decrypt(String model, String iv, String key,String content,String informat) throws Exception
    
```
###### 用例参考：
```
/**
 * AES加解密测试
 * 在线参考网站：@see <a href="http://tool.chacuo.net/cryptaes">在线AES加密解密</a>
 * 加密模式：CBC
 * 填充：PKCS5Padding
 * 数据块：128位
 * 密码：123456
 * 偏移量：12345678bbbbbbbb
 * 输出：BASE64
 * 内容：1.00000000BTC197@TGS#1DGIZOLFO121534146757870
 * @throws Exception
 */
@Test
public void testAES() throws Exception {
    String content = "1.00000000BTC197@TGS#1DGIZOLFO121534146757870";
    String password = "123456";
    //加密
    String encryptResult = AES.encrypt(AES.CBC, "12345678bbbbbbbb", password, content, "BASE64");
    Assert.isTrue(encryptResult.equals("+zFBREntfrB9tQN/UF22rDYF3Hq9eb3qeBO3tz99aaMQed+LOkoyFQ9t07HWvOTf"), "密文不正确！");
    //解密
    String decryptResult = AES.decrypt(AES.CBC, "12345678bbbbbbbb", password, encryptResult, "BASE64");
    Assert.isTrue(content.equals(decryptResult), "解密的明文不正确！");
}
```
- ####  类 Base58
Base58工具类
###### 方法详细说明：
```
/**
 * 对BASE58中的给定字节进行编码。不追加校验和。
 * Encodes the given bytes in base58. No checksum is appended.
 * @param input
 * @return
 */
public static String encode(byte[] input)

/**
 * Base58解码
 * @param input
 * @return
 * @throws IllegalArgumentException
 */
public static byte[] decode(String input) throws IllegalArgumentException
```
###### 用例参考：
```
String txt = "i was a boy you are a girl";
String encode = Base58.encode(txt.getBytes());
System.out.println(encode);
byte[] decode = Base58.decode(encode);
System.out.println(new String(decode));
```
- ####  类 Base64
Base64工具类
###### 方法详细说明：
```
/**
 * 使用Base64加密字符串
 * @return 加密之后的字符串
 * @exception Exception
 */
public static String encode(byte[] data)

/**
 * 使用Base64解密
 * @return 解密之后的字符串
 * @exception Exception
 */
public static byte[] decode(String data)
```

- ####  类 DES
Base64工具类
###### 方法详细说明：
```
/**
 * DES加密
 * 加密模式：CBC
 * 填充：PKCS5Padding
 * 编码：UTF-8
 * 输出：Hex
 * @param srcStr 明文
 * @param sKey 秘钥
 * @return 密文(hex格式)
 */
public static String encrypt(String srcStr, String sKey)


/**
 * DES解密
 * 加密模式：CBC
 * 填充：PKCS5Padding
 * 编码：UTF-8
 * 输出：Hex
 * @param hexStr
 * @param sKey
 * @return 明文内容
 * @throws Exception
 */
public static String decrypt(String hexStr, String sKey) throws Exception
```
###### 用例参考：
```
String afterHex = DES.encrypt("hello world","66666666");
System.out.println("密文："+afterHex);
String orgStr = DES.decrypt(afterHex,"66666666");
System.out.println("明文："+orgStr);
```

- ####  类 Hash
Hash算法
###### 方法详细说明：
```
/**
 * SHA-3算法
 * @param hexInput 16进制字符串
 * @return
 */
public static String sha3Hex(String hexInput)

 /**
 * SHA-3算法
 * @param utf8String
 * @return
 */
public static String sha3(String utf8String)

/**
 * SHA-1算法
 * @param origin
 * @return
 */
public static String sha1(String origin) throws Exception

/**
 * SHA-256算法
 * */
public static String sha256(String data)
```
###### 用例参考：
```
System.out.println(Hash.sha3("hello world"));
System.out.println(Hash.sha3Hex("1F"));
System.out.println(Hash.sha1("hello world"));
System.out.println(Hash.sha256("hello world"));
```
- ####  类 Md5Util
MD5工具类
###### 方法详细说明：
```
/**
 * MD5
 * @param origin
 * @return 32位小写密文
 */
public static String md5(String origin) throws Exception
```
###### 用例参考：
```
/**
 * md5加密
 * 在线md5加解密网站：@see <a href="https://www.sojson.com/encrypt_md5.html">https://www.sojson.com/encrypt_md5.html</a>
 * @throws Exception
 */
@Test
public void md5() throws Exception {
    Assert.assertTrue("5eb63bbbe01eeed093cb22bb8f5acdc3".equals(Md5Util.md5("hello world")));
}
```

- ####  类 PBKDF2
PBKDF2算法
###### 方法详细说明：
```
/**
 * 加密密码
 * @param password 密码明文
 * @return 密文
 */
public static String Encrypt(String password)

/**
 * 验证密码
 * @param password 密码明文
 * @param encrypted 密文
 * @return
 */
public static boolean VerifyString(String password, String encrypted)
```
###### 用例参考：
```
private final String pwd = "123456";

@Test
public void testPBKDF2(){
    String encrypt = PBKDF2.Encrypt(pwd);
    System.out.println(encrypt);
    boolean b = PBKDF2.VerifyString(pwd, encrypt);
    Assert.assertTrue(b);
}
```

- ####  类 RSA
RSA加解密工具类
###### 方法详细说明：
```
/**
 * 随机生成密钥对
 */
public static Map<String, String> genKeyPair()

/**
 * 从字符串中加载公钥
 * @param publicKeyStr 公钥数据字符串
 * @return RSAPublicKey 加载出来的公钥
 * @exception Exception 加载公钥时产生的异常
 */
public static RSAPublicKey loadPublicKeyByStr(String publicKeyStr)

/**
 * 从字符串中加载私钥
 * @param privateKeyStr 私钥数据字符串
 * @return RSAPublicKey 加载出来的私钥
 * @exception Exception 加载私钥时产生的异常
 */
public static RSAPrivateKey loadPrivateKeyByStr(String privateKeyStr)

/**
 * 公钥加密过程
 * @param publicKey 公钥
 * @param plainTextData 明文数据
 * @return byte[] 加密结果
 * @throws Exception 加密过程中的异常信息
 */
public static byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData)

/**
 * 私钥加密过程
 * @param privateKey 私钥
 * @param plainTextData 明文数据
 * @return byte[] 加密结果
 * @throws Exception 加密过程中的异常信息
 */
public static byte[] encrypt(RSAPrivateKey privateKey, byte[] plainTextData)

/**
 * 私钥解密过程
 * @param privateKey 私钥
 * @param cipherData 密文数据
 * @return 明文
 * @throws Exception 解密过程中的异常信息
 */
public static byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData)

/**
 * 公钥解密过程
 * @param publicKey 公钥
 * @param cipherData 密文数据
 * @return 明文
 * @throws Exception 解密过程中的异常信息
 */
public static byte[] decrypt(RSAPublicKey publicKey, byte[] cipherData)

/**
 * 获取私钥
 * @param keyMap 密钥对
 * @return
 * @throws Exception
 */
public static String getPrivateKey(Map<String, String> keyMap)

/**
 * 获取公钥
 * @param keyMap 密钥对
 * @return
 * @throws Exception
 */
public static String getPublicKey(Map<String, String> keyMap)
```
###### 用例参考：
```
//明文
String text = "123qwe456asd";
System.out.println("明文：" + text);

// 生成公私钥
Map<String, String> keyMap = RSA.genKeyPair();
// 获取公钥
String publicKey = RSA.getPublicKey(keyMap);
System.out.println("公钥："+ publicKey);
RSAPublicKey rsaPublicKey = RSA.loadPublicKeyByStr(publicKey);

// 获取私钥
String privateKey = RSA.getPrivateKey(keyMap);
System.out.println("私钥："+ privateKey);
RSAPrivateKey rsaPrivateKey = RSA.loadPrivateKeyByStr(privateKey);

//私钥加密，公钥解密
byte[] encrypt = RSA.encrypt(rsaPrivateKey, text.getBytes());
System.out.println("私钥加密：" + Base64.encode(encrypt));
byte[] decrypt = RSA.decrypt(rsaPublicKey, encrypt);
System.out.println("公钥解密："+new String( decrypt) );

//公钥加密，私钥解密
byte[] encrypt2 = RSA.encrypt(rsaPublicKey, text.getBytes());
System.out.println("公钥加密：" + Base64.encode(encrypt2));
byte[] decrypt2 = RSA.decrypt(rsaPrivateKey, encrypt2);
System.out.println("私钥解密："+new String( decrypt2) );
```

- ####  类 SignUtil
SignUtil签名工具类
###### 方法详细说明：
```
/**
 * SHA256WithRSA签名
 * @param data
 * @param privateKey
 * @return
 * @throws NoSuchAlgorithmException
 * @throws InvalidKeySpecException
 * @throws InvalidKeyException
 * @throws SignatureException
 * @throws UnsupportedEncodingException
 */
public static byte[] sign256(String data, PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException,
        SignatureException, UnsupportedEncodingException
        
/**
 * 验证SHA256WithRSA签名
 * @param data
 * @param sign
 * @param publicKey
 * @return
 */
public static boolean verify256(String data, byte[] sign, PublicKey publicKey)
```
###### 用例参考：
```
//明文
String text = "123qwe456asd";
System.out.println("明文：" + text);

// 生成公私钥
Map<String, String> keyMap = RSA.genKeyPair();
// 获取公钥
String publicKey = RSA.getPublicKey(keyMap);
System.out.println("公钥："+ publicKey);
RSAPublicKey rsaPublicKey = RSA.loadPublicKeyByStr(publicKey);

// 获取私钥
String privateKey = RSA.getPrivateKey(keyMap);
System.out.println("私钥："+ privateKey);
RSAPrivateKey rsaPrivateKey = RSA.loadPrivateKeyByStr(privateKey);

byte[] bytes = SignUtil.sign256(text, rsaPrivateKey);
System.out.println("签名："+ Base64.encode(bytes));

boolean b = SignUtil.verify256(text, bytes, rsaPublicKey);
System.out.println("验签：" + b);
```

### com.zhongan.swzc.common.utils.data ：数据处理
- ####  类 ByteUtil
Byte工具类
###### 方法详细说明：
```
/**
 * 从byte[]中抽取新的byte[]
 * @param data - 元数据
 * @param start - 开始位置
 * @param end - 结束位置
 * @return 新byte[]
 */
public static byte[] getByteArr(byte[]data,int start ,int end)

/**
 * 流转换为byte[]
 * @param inStream
 * @return
 */
public static byte[] readInputStream(InputStream inStream)

/**
 * byte[]转inputstream
 * @param b
 * @return
 */
public static InputStream readBytes(byte[] b)

/**
 * byte数组内数字是否相同
 * @param s1
 * @param s2
 * @return
 */
public static boolean isEqual(byte[] s1, byte[] s2)

/**
 * 合并两个byte数组
 * @param bt1
 * @return
 */
public static byte[] mergeByte(byte[] bt1, byte[] bt2)

/**
 *拆分数组
 * @param data
 * @param len
 * @return
 */
public static byte[][] splitArray(byte[] data,int len)

/**
 * 比较两个byte数组
 * @param bt1
 * @param bt2
 * @return
 */
public static boolean compareByte(byte[] bt1, byte[] bt2)
```

- ####  类 DataUtil
基本数据互转工具
###### 方法详细说明：
```
/**
 * int转byte
 * @param x
 * @return
 */
public static byte toByte(int x)

/**
 * int转byte[]
 * @param a
 * @return
 */
public static byte[] toBytes(int a)

/**
 * 16位short转byte[]
 * @param s
 * @return byte[]
 * */
public static byte[] toBytes(short s)

/**
 * long转byte[]
 * @param x
 * @return
 */
public static byte[] toBytes(long x)

/**
 * 将16进制字符串转换byte数组
 * @param hexStr
 * @return
 */
public static byte[] hexStringToBytes(String hexStr)

/**
 * byte[]转16位short
 * @param b
 * @return
 */
public static short toShort(byte[] b)

/**
 * byte[]转short  
 * @param b
 * @param index
 * @return
 */
public static short toShort(byte[] b, int index)

/**
 * byte转int
 * @param b
 * @return
 */
public static int toInt(byte b)

/**
 * byte[]转int
 * @param b
 * @return
 */
public static int toInt(byte[] b)

/**
 * byte[]转int
 * @param b
 * @param index
 * @return
 */
public static int toInt(byte[] b, int index)

/**
 * 16进制字符创转int
 * @param hexString
 * @return
 */
public static int hexStringToInt(String hexString)

/**
 * byte[]转Long 
 * @param bytes
 * @return
 */
public static long toLong(byte[] bytes)

/**
 * byte数组转换为Stirng
 * @param s1-数组
 * @param encode-字符集
 * @return
 */
public static String toString(byte[] s1, String encode)

/**
 * byte数组转换为Stirng 
 * @param s1 -数组 
 * @param encode -字符集 
 * @param err -转换错误时返回该文字 
 * @return
 */
public static String toString(byte[] s1, String encode, String err)

/**
 * 字节数组转16进制字符串(小写)
 * @param b
 * @return
 */
public static String toHexString(byte[] b)

/**
 * 将数字转为十六进制字符串, 默认要使用2个字符(暂时没考虑负数)
 *
 * @param n
 *            数字
 * @return 十六进制字符串
 */
public static String toHexString(int n)

/**
 * 十进制转二进制 
 * @param i
 * @return
 */
public static String toBinary(int i)

/**
 * 字符串转16进制byte
 * @param string
 * @return
 */
public static byte[] toHex(String string)
    
```
- ####  类 NumsUtil
数字工具类
###### 方法详细说明：
```
/**
 * 将一个字符串变成一个整型数组，如果字符串不符合规则，对应的元素为 -1 <br>
 * 比如：
 *
 * <pre>
 * "3,4,9"   =>  [  3, 4, 9 ]
 * "a,9,100" =>  [ -1, 9, 100 ]
 * </pre>
 *
 * @param str
 *            半角逗号分隔的数字字符串
 * @return 数组
 */
public static int[] splitInt(String str)

/**
 * 将一个字符串变成一个浮点数数组，如果字符串不符合规则，对应的元素为 0.0 <br>
 * 比如：
 *
 * <pre>
 * "3,4,9"     =>  [ 3.0f, 4.0f, 9.0f ]
 * "a,9.8,100" =>  [ 0.0f, 9.0f, 100.0f ]
 * </pre>
 *
 * @param str
 *            半角逗号分隔的数字字符串
 * @return 数组
 */
public static float[] splitFloat(String str)

/**
 * 将一个字符串变成一个双精度数数组，如果字符串不符合规则，对应的元素为 -1
 *
 * @param str
 *            半角逗号分隔的数字字符串
 * @return 数组
 */
public static double[] splitDouble(String str)

// ....
```
### com.zhongan.swzc.common.utils.datetime ：日期时间
- ####  类 DateTimeUtil
日期时间工具类
###### 方法详细说明：
```
/**
* 获取当前日期
* @return
*/
public static LocalDate getLocalDate()

/**
* 获取当前时间
* @return
*/
public static LocalTime getLocalTime()

/**
* 获取当前日期时间
* @return
*/
public static LocalDateTime getLocalDateTime()

/**
* 获取指定日期
* @param year
* @param month
* @param day
* @return
*/
public static LocalDate getLocalDate(int year, int month, int day)

/**
* 判断今天是不是重要月日（比如生日）
* @param year
* @param month
* @param day
* @return
*/
public static Boolean isBirthday(int year, int month, int day)

/**
* 判断今天是不是重要年月（比如信用卡到期月份）
* @param year
* @param month
* @return
*/
public static Boolean isYearMonth(int year, int month)

/**
* localDateTime 转 自定义格式string
*
* @param localDateTime
* @param format        例：yyyy-MM-dd hh:mm:ss
* @return
*/
public static String formatLocalDateTimeToString(LocalDateTime localDateTime, String format)

/**
* 根据时间获取当月有多少天数
*
* @param date
* @return
*/
public static int getActualMaximum(Date date)

/**
 * 根据日期获得星期
 *
 * @param date
 * @return 1:星期一；2:星期二；3:星期三；4:星期四；5:星期五；6:星期六；7:星期日；
 */
public static int getWeekOfDate(Date date)

//...
```
###### 用例参考：
```
String str = "2018-09-30 14:46:54";
String dbTimePattern = DateTimeUtil.TIME_PATTERN;
System.out.println(DateTimeUtil.stringToLocalDateTime(str, dbTimePattern));
```
### com.zhongan.swzc.common.utils.id ： ID生成
- ####  类 IdWorker
ID生成器
###### 方法详细说明：
```
/**
 *  初始化ID生成算法
 *  @param machineid 机器的编号，最大值允许为255
 */
public static synchronized void init(int machineid)

/**
 *  生成ID
 *  @return 生成的ID
 */
public static long generateId() throws InterruptedException
```
###### 用例参考：
```
IdWorker.init(5);
System.out.println(IdWorker.generateId());
```

### com.zhongan.swzc.common.utils.json ： JSON处理
- ####  类 JsonUtils
JSON格式化工具类
###### 方法详细说明：
```
/**
 * 转换成JSON格式的字符串
 *
 * @param object
 * @return
 */
public static String toJSONString(Object object)

/**
 * 把JSON格式的字符串解析成普通对象。比如：<br/>
 * <code><blockquote>
 * UserDTO dto = BaseDto.fromJson(str, UserDTO.class);
 * </blockquote></code>
 *
 * @param json
 * @param classOfT
 * @return
 */
public static <T> T toJsonObject(String json, Class<T> classOfT)

/**
 * 把JSON格式的字符串解析成泛型类。比如：<br/>
 * <code><blockquote>
 * Map&lt;String, Object&gt; map = BaseDto.fromJson(str, new TypeReference&lt;Map&lt;String, Object&gt;&gt;() {});
 * </blockquote></code>
 *
 * @param json
 * @param typeOfT
 * @return
 */
public static <T> T toJsonObject(String json, TypeReference<T> typeOfT)

/**
 * 装换JSON字符串为数组
 * @param text
 * @param <T>
 * @return
 */
public static <T> Object[] toArray(String text)

/**
 * 装换JSON字符串为数组
 * @param text
 * @param <T>
 * @return
 */
public static <T> Object[] toArray(String text, Class<T> clazz)

/**
 * 转换JSON字符串为List
 * @param text
 * @param clazz
 * @param <T>
 * @return
 */
public static <T> List<T> toList(String text, Class<T> clazz)

/**
 * 将string转化为序列化的json字符串
 * @param text
 * @return
 */
public static Object textToJson(String text)

/**
 * json字符串转化为map
 * @param s
 * @return
 */
public static Map stringToMap(String s)

/**
 * 将map转化为json字符串
 * @param m
 * @return
 */
public static String mapToString(Map m)
```
###### 用例参考：
```
@Test
public void testToString() throws Exception {
    User jack = new User("Jack", 18);
    String s = JsonUtils.toJSONString(jack);
    System.out.println(s);
}

@Test
public void fromJson() throws Exception {
    User user = JsonUtils.toJsonObject("{\"name\":\"Jack\",\"age\":18}", User.class);
    System.out.println(user);
}

@Test
public void fromJson1() throws Exception {
    List<String> list = new ArrayList<String>();
    list.add("json1");
    list.add("json2");
    list.add("json3");
    String jsonStr = JsonUtils.toJSONString(list);
    System.out.println(jsonStr);
    List<String> list2 = JsonUtils.toJsonObject(jsonStr, new TypeReference<List<String>>() {});
    System.out.println(list2);
}
```
### com.zhongan.swzc.common.utils.math ： 数学工具、随机数等
- ####  类 BigDecimalUtil
BigDecimal帮助类
###### 方法详细说明：
```
/**
 * 加
 * @param v1
 * @param v2
 * @return
 */
public static BigDecimal add(double v1,double v2)

/**
 * 减
 * @param v1
 * @param v2
 * @return
 */
public static BigDecimal sub(double v1,double v2)

/**
 * 乘
 * @param v1
 * @param v2
 * @return
 */
public static BigDecimal mul(double v1,double v2)

/**
 * 除
 * @param v1
 * @param v2
 * @return
 */
public static BigDecimal div(double v1,double v2)
```
- ####  类 R
Random随机类
###### 方法详细说明：
```
/**
 * 根据一个范围，生成一个随机的整数
 *
 * @param min
 *            最小值（包括）
 * @param max
 *            最大值（包括）
 * @return 随机数
 */
public static int random(int min, int max)

/**
 * 根据一个长度范围，生成一个随机的字符串，字符串内容为 [0-9a-zA-Z_]
 *
 * @param min
 *            最小值（包括）
 * @param max
 *            最大值（包括）
 * @return 随机字符串
 */

public static StringGenerator sg(int min, int max)

/**
 * 返回指定长度随机数字+字母(大小写敏感)组成的字符串
 *
 * @param length
 *            指定长度
 * @param caseSensitivity
 *            是否区分大小写
 * @return 随机字符串
 */
public static String captchaChar(int length, boolean caseSensitivity)

/**
 * 返回指定长度随机数字组成的字符串
 *
 * @param length
 *            指定长度
 * @return 随机字符串
 */
public static String captchaNumber(int length)

/**
 * @return 64进制表示的紧凑格式的 UUID
 */
public static String UU64()

/**
 * 从一个 UU64 恢复回一个 UUID 对象
 *
 * @param uu64
 *            64进制表示的 UUID, 内容为 [\\-0-9a-zA-Z_]
 * @return UUID 对象
 */
public static UUID fromUU64(String uu64)

//...
```

- ####  类 SequenceNoUtil
序列号生成工具
###### 方法详细说明：
```
/**
 * 生成订单号
 * 格式为日期（14位数字）+ 6位数字和英文混合 + 用户账户ID
 * @return
 */
public static String createTransNo(Long acctId)
```
###### 用例参考：
```
String transNo = SequenceNoUtil.createTransNo(109L);
System.out.println(transNo);
```

- ####  类 StringGenerator
随机字符串生成器
###### 方法详细说明：
```
**
 * 根据设置的max和min的长度,生成随机字符串.
 * <p/>
 * 若max或min小于0,则返回null
 *
 * @return 生成的字符串
 */
public String next()
```

###### 用例参考：
```
StringGenerator stringGenerator = new StringGenerator(1, 100);
System.out.println(stringGenerator.next());
```

### com.zhongan.swzc.common.utils.network ： 网络工具
- ####  类 IPUtil
IP工具类
###### 方法详细说明：
```
/**
 * 获得服务器的IP地址
 *
 * @return
 */
public static String getLocalIP()

/**
 * 获得服务器的IP地址(多网卡)
 *
 * @return
 */
public static List<String> getLocalIPs()

/**
 * 获得服务器的MAC地址
 *
 * @return
 */
public static String getMacId()

/**
 * 获得服务器的MAC地址(多网卡)
 *
 * @return
 */
public static List<String> getMacIds()
```
###### 用例参考：
```
@Test
public void getLocalIP() throws Exception {
    System.out.println(IPUtil.getLocalIP());
}

@Test
public void getLocalIPS() throws Exception {
    System.out.println(IPUtil.getLocalIPs());
}

@Test
public void getMacId() throws Exception {
    System.out.println(IPUtil.getMacId());
}

@Test
public void getMacIds() throws Exception {
    System.out.println(IPUtil.getMacIds());
}
```
- ####  类 RequestUtil
Request工具类
###### 方法详细说明
```
/**
 * 获取客户端IP地址，此方法用在proxy环境中
 *
 * @param req
 * @return
 */
public static String getRemoteAddr(HttpServletRequest req)

/**
 * 获取用户访问URL中的根域名
 * 例如: www.dlog.cn -> dlog.cn
 *
 * @param host
 * @return
 */
public static String getDomainOfServerName(String host)

/**
 * 判断字符串是否是一个IP地址
 *
 * @param addr
 * @return
 */
public static boolean isIPAddr(String addr)

/**
 * 获取HTTP端口
 *
 * @param req
 * @return
 * @throws MalformedURLException
 */
public static int getHttpPort(HttpServletRequest req)

/**
 * 获取URI
 * @param request
 * @return
 */
public static Object getUrl(HttpServletRequest request)

/**
 * 获取user-agent
 * @param request
 * @return
 */
public static String getUserAgent(HttpServletRequest request)

/**
 * 获取请求Body
 *
 * @param request
 * @return
 */
public static String getBodyString(ServletRequest request)
    
```

- ####  类 UnirestUtil
http请求工具类
###### 方法详细说明：
```
/**
 * get请求
 * @param url
 * @return
 * @throws UnirestException
 */
public static String get(String url)

/**
 * get请求
 * @param url
 * @param parameters
 * @param respClass
 * @param <T>
 * @return
 * @throws UnirestException
 */
public static <T> T get(String url,Map<String,Object> parameters,Class<T> respClass) throws UnirestException

/**
 * get请求
 * @param url
 * @param parameters
 * @return
 * @throws UnirestException
 */
public static String get(String url,Map<String,Object> parameters) throws UnirestException

/**
 * Post请求
 * @param url
 * @param requestBody
 * @param respClass
 * @param <T>
 * @return
 * @throws UnirestException
 */
public static <T> T post(String url,Object requestBody,Class<T> respClass) throws UnirestException

/**
 * 表单提交
 * @param url
 * @param requestBody
 * @param respClass
 * @param <T>
 * @return
 * @throws UnirestException
 */
public static <T> T postForm(String url,Map<String,Object> requestBody,Class<T> respClass) throws UnirestException
```
###### 用例参考：
```
@Test
public void get() throws Exception {
    String response = UnirestUtil.get("https://www.baidu.com");
    System.out.println(response);
}

@Test
public void post() throws Exception {
    Request request = new Request();
    request.setCode("123");
    request.setOperate("str");
    Response response = UnirestUtil.post("https://tool.lu/hexstr/ajax.html", request, Response.class);
    System.out.println(JsonUtils.toJSONString(response));
}
```

### com.zhongan.swzc.common.utils.other ： 其他
- ####  类 ThreadLocalUtils
本地线程副本变量工具类


### com.zhongan.swzc.common.utils.spring ： spring工具
- ####  类 SpringUtil
Spring工具类
###### 方法详细说明：
```
/**
 * 获取applicationContext
 * @return
 */
public static ApplicationContext getApplicationContext()

/**
 * 通过name获取 Bean.
 * @param name
 * @return
 */
public static Object getBean(String name)

/**
 * 通过class获取Bean
 * @param clazz
 * @param <T>
 * @return
 */
public static <T> T getBean(Class<T> clazz)

/**
 * 通过name,以及Clazz返回指定的Bean
 * @param name
 * @param clazz
 * @param <T>
 * @return
 */
public static <T> T getBean(String name, Class<T> clazz)
```

### com.zhongan.swzc.common.utils.string ： 字符串处理
- ####  类 StringUtil
字符串工具类
###### 方法详细说明：
```
/** 
 * 拆分字符串成数组
 * @param string
 * @param len
 * @return
 */  
public static String[] splitString(String string, int len)

/**
 * Map 转化为String
 * @param map
 * @return
 */
public static String mapToString(Map<String,String> map)

/**
 * 脱敏
 * @param value
 * @return
 */
public static String toConceal(String value)

/**
 * <p>Checks if a CharSequence is whitespace, empty ("") or null.</p>
 *
 * <pre>
 * StringUtils.isBlank(null)      = true
 * StringUtils.isBlank("")        = true
 * StringUtils.isBlank(" ")       = true
 * StringUtils.isBlank("bob")     = false
 * StringUtils.isBlank("  bob  ") = false
 * </pre>
 *
 * @param cs  the CharSequence to check, may be null
 * @return {@code true} if the CharSequence is null, empty or whitespace
 */
public static boolean isBlank(CharSequence cs)

/**
 * <p>Checks if a CharSequence is not empty (""), not null and not whitespace only.</p>
 *
 * <pre>
 * StringUtils.isNotBlank(null)      = false
 * StringUtils.isNotBlank("")        = false
 * StringUtils.isNotBlank(" ")       = false
 * StringUtils.isNotBlank("bob")     = true
 * StringUtils.isNotBlank("  bob  ") = true
 * </pre>
 *
 * @param cs  the CharSequence to check, may be null
 * @return {@code true} if the CharSequence is
 *  not empty and not null and not whitespace
 */
public static boolean isNotBlank(CharSequence cs)

/**
 * <p>Checks if a CharSequence is empty ("") or null.</p>
 *
 * <pre>
 * StringUtils.isEmpty(null)      = true
 * StringUtils.isEmpty("")        = true
 * StringUtils.isEmpty(" ")       = false
 * StringUtils.isEmpty("bob")     = false
 * StringUtils.isEmpty("  bob  ") = false
 * </pre>
 *
 * <p>NOTE: This method changed in Lang version 2.0.
 * It no longer trims the CharSequence.
 * That functionality is available in isBlank().</p>
 *
 * @param cs  the CharSequence to check, may be null
 */
public static boolean isEmpty(CharSequence cs)

/**
 * <p>Checks if a CharSequence is not empty ("") and not null.</p>
 *
 * <pre>
 * StringUtils.isNotEmpty(null)      = false
 * StringUtils.isNotEmpty("")        = false
 * StringUtils.isNotEmpty(" ")       = true
 * StringUtils.isNotEmpty("bob")     = true
 * StringUtils.isNotEmpty("  bob  ") = true
 * </pre>
 *
 * @param cs  the CharSequence to check, may be null
 */
public static boolean isNotEmpty(CharSequence cs)

//...
```
###### 用例参考：
```
@Test
public void splitString() throws Exception {
    System.out.println(Arrays.asList(StringUtil.splitString("zhonganinfo", 3)));
}

@Test
public void mapToString() throws Exception {
    Map<String, String> map = new HashMap<>();
    map.put("name","jack");
    map.put("age","18");
    System.out.println(StringUtil.mapToString(map));
}

@Test
public void toConceal() throws Exception {
    System.out.println(StringUtil.toConceal("13812345678"));
}

@Test
public void isBlank() throws Exception {
    System.out.println(StringUtil.isBlank(""));
    System.out.println(StringUtil.isBlank(" "));
    System.out.println(StringUtil.isBlank("a"));
}

@Test
public void isNotBlank() throws Exception {
    System.out.println(StringUtil.isNotBlank(""));
    System.out.println(StringUtil.isNotBlank(" "));
    System.out.println(StringUtil.isNotBlank("a"));
}

@Test
public void isEmpty() throws Exception {
    System.out.println(StringUtil.isEmpty(""));
    System.out.println(StringUtil.isEmpty(" "));
    System.out.println(StringUtil.isEmpty("a"));
}

@Test
public void isNotEmpty() throws Exception {
    System.out.println(StringUtil.isNotEmpty(""));
    System.out.println(StringUtil.isNotEmpty(" "));
    System.out.println(StringUtil.isNotEmpty("a"));
}

@Test
public void getKey() throws Exception {
    System.out.println(StringUtil.getKey("name", "jack", "age", 18));
}

@Test
public void getParams() throws Exception {
    System.out.println(Arrays.asList(StringUtil.getParams("name_jack_age_18", "_")));
}

@Test
public void splitIgnoreBlank() throws Exception {
    System.out.println(Arrays.asList(StringUtil.splitIgnoreBlank("A,B,C")));
}

@Test
public void splitIgnoreBlank1() throws Exception {
    System.out.println(Arrays.asList(StringUtil.splitIgnoreBlank("A_B_C", "_")));
}

@Test
public void trim() throws Exception {
    System.out.println(StringUtil.trim(" ni hao "));
}

@Test
public void alignRight() throws Exception {
    System.out.println(StringUtil.alignRight("hello", 9, 'a'));
}

@Test
public void alignLeft() throws Exception {
    System.out.println(StringUtil.alignLeft("hello", 9, 'a'));
}

@Test
public void dup() throws Exception {
    System.out.println(StringUtil.dup('c',8));
}

@Test
public void lowerWord() throws Exception {
    System.out.println(StringUtil.lowerWord("helloWorld", '-'));
}

@Test
public void upperWord() throws Exception {
    System.out.println(StringUtil.upperWord("hello-world", '-'));
}

@Test
public void escapeHtml() throws Exception {
    System.out.println(StringUtil.escapeHtml("<html>hello</html>"));
}
```

### com.zhongan.swzc.common.utils.system ： 系统工具
- ####  类 OSUtil
操作系统工具类
###### 方法详细说明：
```
/**
 * 判断当前操作是否Windows.
 * @return true---是Windows操作系统
 */
public static boolean isWindowsOS()
```

### com.zhongan.swzc.common.utils.validate ： 正则验证
- ####  类 RegexUtil
正则工具类
###### 方法详细说明：
```
/**
 * 校验大陆手机号
 *
 * @param mobile
 * @return 校验通过返回true，否则返回false
 */
public static boolean isMobile(String mobile)

/**
 * 香港手机号码8位数，5|6|8|9开头+7位任意数
 */
public static boolean isHKPhoneLegal(String str)

/**
 * 校验邮箱
 *
 * @param email
 * @return 校验通过返回true，否则返回false
 */
public static boolean isEmail(String email)

/**
 * 校验汉字
 *
 * @param chinese
 * @return 校验通过返回true，否则返回false
 */
public static boolean isChinese(String chinese)

/**
 * 校验身份证
 *
 * @param idCard
 * @return 校验通过返回true，否则返回false
 */
public static boolean isIDCard(String idCard)

/**
 * 校验URL
 *
 * @param url
 * @return 校验通过返回true，否则返回false
 */
public static boolean isUrl(String url)

/**
 * 校验IP地址
 *
 * @param ipAddr
 * @return
 */
public static boolean isIPAddr(String ipAddr)

/**
 * 校验银行卡卡号
 * 校验过程：
 * 1、从卡号最后一位数字开始，逆向将奇数位(1、3、5等等)相加。
 * 2、从卡号最后一位数字开始，逆向将偶数位数字，先乘以2（如果乘积为两位数，将个位十位数字相加，即将其减去9），再求和。
 * 3、将奇数位总和加上偶数位总和，结果应该可以被10整除。
 */
public static boolean isBankCard(String bankCard)

/**
 * 从不含校验位的银行卡卡号采用 Luhm 校验算法获得校验位
 *
 * @param nonCheckCodeBankCard
 * @return
 */
public static char getBankCardCheckCode(String nonCheckCodeBankCard)
```
