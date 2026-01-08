use anyhow::{Result, Context};

/// SSH version string format: SSH-<protocol>-<software>[comments]\r\n
#[derive(Debug, Clone, PartialEq)]
pub struct VersionString {
    pub protocol: String,
    pub software: String,
    pub comments: Option<String>,
}

impl VersionString {
    /// Create a new version string
    pub fn new(protocol: &str, software: &str, comments: Option<&str>) -> Self {
        Self {
            protocol: protocol.to_string(),
            software: software.to_string(),
            comments: comments.map(|s| s.to_string()),
        }
    }

    /// Parse a version string from bytes
    pub fn parse(data: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(data)
            .context("Invalid UTF-8 in version string")?;
        
        Self::parse_str(text)
    }

    /// Parse a version string from a string slice
    pub fn parse_str(text: &str) -> Result<Self> {
        // Remove trailing \r\n if present
        let text = text.trim_end_matches("\r\n").trim_end_matches('\n');
        
        // Version string format: SSH-<protocol>-<software>[comments]
        if !text.starts_with("SSH-") {
            anyhow::bail!("Version string must start with 'SSH-'");
        }

        let rest = &text[4..]; // Skip "SSH-"
        
        // Find the protocol version (between first and second dash)
        let parts: Vec<&str> = rest.splitn(2, '-').collect();
        if parts.len() < 2 {
            anyhow::bail!("Invalid version string format: missing protocol or software version");
        }

        let protocol = parts[0].to_string();
        let rest = parts[1];

        // Check for optional comments (space-separated)
        let (software, comments) = if let Some(space_idx) = rest.find(' ') {
            let (sw, cmt) = rest.split_at(space_idx);
            (sw.to_string(), Some(cmt[1..].to_string()))
        } else {
            (rest.to_string(), None)
        };

        Ok(Self {
            protocol,
            software,
            comments,
        })
    }

    /// Convert version string to wire format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = format!("SSH-{}-{}", self.protocol, self.software);
        if let Some(ref comments) = self.comments {
            result.push(' ');
            result.push_str(comments);
        }
        result.push_str("\r\n");
        result.into_bytes()
    }

    /// Get the full version string as a string
    pub fn to_string(&self) -> String {
        String::from_utf8(self.to_bytes()).unwrap()
    }
}

impl std::fmt::Display for VersionString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SSH-{}-{}", self.protocol, self.software)?;
        if let Some(ref comments) = self.comments {
            write!(f, " {}", comments)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_string() {
        let data = b"SSH-2.0-OpenSSH_8.9\r\n";
        let version = VersionString::parse(data).unwrap();
        assert_eq!(version.protocol, "2.0");
        assert_eq!(version.software, "OpenSSH_8.9");
        assert_eq!(version.comments, None);
    }

    #[test]
    fn test_parse_version_with_comments() {
        let data = b"SSH-2.0-OpenSSH_8.9 Ubuntu-1ubuntu1\r\n";
        let version = VersionString::parse(data).unwrap();
        assert_eq!(version.protocol, "2.0");
        assert_eq!(version.software, "OpenSSH_8.9");
        assert_eq!(version.comments, Some("Ubuntu-1ubuntu1".to_string()));
    }

    #[test]
    fn test_version_to_bytes() {
        let version = VersionString::new("2.0", "MySSH_1.0", None);
        let bytes = version.to_bytes();
        assert_eq!(bytes, b"SSH-2.0-MySSH_1.0\r\n");
    }
}

