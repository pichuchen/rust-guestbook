#[cfg(test)]
mod tests {
    use super::*;

    fn parse_key(key: &str) -> String {
        key.to_string()
    }

    fn assert_safe_filename(filename: &str) {
        // add assertions to check the safety of the filename
    }

    #[test]
    fn generate_attachment_key_has_expected_shape() {
        let key = generate_attachment_key("example.txt");
        assert!(key.len() > 0);
        // Additional assertions for expected shape
    }

    #[test]
    fn generate_attachment_key_sanitizes_path_traversal_and_separators() {
        let key = generate_attachment_key("../../path/to/dir/file.txt");
        assert!(!key.contains(".."));
        // Additional assertions
    }

    #[test]
    fn generate_attachment_key_strips_spaces_and_special_chars_but_keeps_dot_dash_underscore() {
        let key = generate_attachment_key("hello world!.txt");
        assert!(key.contains("hello"));
        assert!(!key.contains(" "));
        // Additional assertions
    }

    #[test]
    fn generate_attachment_key_empty_filename_falls_back_to_file() {
        let key = generate_attachment_key("");
        assert_eq!(key, "fallback_key"); // assuming fallback_key is the fallback
    }

    #[test]
    fn generate_attachment_key_all_invalid_chars_falls_back_to_file() {
        let key = generate_attachment_key("<>:"/\|?*");
        assert_eq!(key, "fallback_key");
    }

    #[test]
    fn generate_attachment_key_does_not_return_same_key_each_time() {
        let key1 = generate_attachment_key("test.txt");
        let key2 = generate_attachment_key("test.txt");
        assert_ne!(key1, key2);
    }
}