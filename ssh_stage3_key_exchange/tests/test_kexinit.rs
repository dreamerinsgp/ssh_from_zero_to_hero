use ssh_stage3_key_exchange::key_exchange::KexInit;
use ssh_stage3_key_exchange::message::MessageType;

#[test]
fn test_understand_kexinit() {
    // ============================================
    // 理解 KexInit：类比解释
    // ============================================
    // 【类比1：餐厅菜单】KexInit 就像一份餐厅菜单，告诉对方"我能提供什么"：
    // - 我能做哪些菜（支持的算法）、我有哪些调料（加密方式、MAC算法等）
    // 【类比2：谈判前的准备】就像两个人谈判前，先互相展示自己的"能力清单"
    // 【核心概念】KexInit = 算法能力清单 + 随机cookie（防止重放攻击）
    
    // ============================================
    // 步骤1：创建 KexInit（就像写一份菜单）
    // ============================================
    let client_kex = KexInit::new();
    
    // 【具体示例】查看创建的内容
    // cookie 是16字节的随机数，就像每份菜单的"唯一编号"
    // 防止攻击者重放旧的菜单（重放攻击）
    assert_eq!(client_kex.cookie.len(), 16, 
        "cookie应该是16字节，用于防止重放攻击");
    
    // 【具体示例】查看支持的算法
    // 就像菜单上列出"我们有：川菜、粤菜、湘菜"
    assert!(!client_kex.kex_algorithms.is_empty(),
        "应该至少支持一种密钥交换算法");
    assert!(!client_kex.encryption_algorithms_client_to_server.is_empty(),
        "应该至少支持一种加密算法");
    
    // ============================================
    // 步骤2：转换为字节（就像把菜单打印成纸质版）
    // ============================================
    // 【类比】to_bytes() 把内存中的结构体转换成可网络传输的字节数组
    let client_kex_bytes = client_kex.to_bytes();
    
    // 【验证1】字节数组不应该为空
    assert!(!client_kex_bytes.is_empty(), 
        "序列化后的字节数组不应该为空");
    
    // 【验证2】第一个字节应该是消息类型
    // SSH协议规定：KEXINIT消息的第一个字节是消息类型（20）
    let expected_msg_type = MessageType::KeyExchangeInit.to_u8();
    assert_eq!(client_kex_bytes[0], expected_msg_type,
        "第一个字节应该是SSH_MSG_KEXINIT的消息类型（20）");
    
    // 【验证3】接下来的16字节应该是cookie
    // 就像菜单的第一行是"菜单编号：XXXX"
    assert!(client_kex_bytes.len() > 17,
        "字节数组应该包含消息类型(1字节) + cookie(16字节) + 其他内容");
    
    // ============================================
    // 步骤3：验证序列化和反序列化的对称性
    // ============================================
    // 【类比】就像把菜单打印出来，再扫描识别回去，应该内容一致
    // 创建第二个KexInit（会生成不同的cookie）
    let client_kex2 = KexInit::new();
    let _client_kex2_bytes = client_kex2.to_bytes();
    
    // 【验证】两次创建的cookie应该不同（随机性）
    // 就像两份菜单的编号应该不同
    assert_ne!(client_kex.cookie, client_kex2.cookie,
        "每次创建的cookie应该不同（随机生成）");
    
    // 【验证】但算法列表应该相同（都使用默认配置）
    assert_eq!(client_kex.kex_algorithms, client_kex2.kex_algorithms,
        "使用相同配置创建的KexInit，算法列表应该相同");
    
    // ============================================
    // 步骤4：理解为什么需要 to_bytes()
    // ============================================
    // 【类比】网络传输就像寄信：内存中的结构体=想法（不能邮寄），字节数组=信（可以邮寄）
    // 【具体示例】字节数组格式：[消息类型][cookie][算法列表...]
    let _msg_type_byte = client_kex_bytes[0];
    let cookie_start = 1;
    let cookie_end = cookie_start + 16;
    
    // 提取cookie部分
    let extracted_cookie: [u8; 16] = client_kex_bytes[cookie_start..cookie_end]
        .try_into()
        .expect("应该能提取16字节的cookie");
    
    // 【验证】提取的cookie应该和原始cookie一致
    assert_eq!(extracted_cookie, client_kex.cookie,
        "从字节数组中提取的cookie应该和原始cookie一致");
    
    // ============================================
    // 总结：KexInit 的本质
    // ============================================
    // 1. KexInit::new() 创建"能力清单"（包含随机cookie）
    // 2. to_bytes() 把清单转换成可网络传输的格式
    // 3. 客户端和服务器互相发送KexInit，然后协商共同支持的算法
    // 【类比总结】KexInit=菜单，to_bytes()=打印菜单，cookie=菜单编号，算法列表=菜品
    
    println!("✓ KexInit创建成功，包含{}种密钥交换算法", client_kex.kex_algorithms.len());
    println!("✓ 序列化后的字节数组长度：{}字节", client_kex_bytes.len());
    println!("✓ Cookie（前4字节）：{:02x?}", &client_kex.cookie[..4]);
}

