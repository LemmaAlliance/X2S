# Tests Directory

This directory is prepared for future unit tests.

## Current Testing

Currently, X2S uses shell-based end-to-end tests (see `e2e_local.sh` in the project root). The CI pipeline runs these tests automatically.

## Adding Unit Tests

When you're ready to add unit tests, follow these steps:

### 1. Choose a test framework

Recommended lightweight C test frameworks:
- **Check** - `sudo apt install check` - Feature-rich, well-maintained
- **Unity** - Single-file, minimal dependencies
- **Custom** - Roll your own with simple assertions

### 2. Create test files

Example structure:
```
tests/
  CMakeLists.txt          # Test build configuration
  test_auth.c             # Auth module tests
  test_obj_operations.c   # Object operations tests
  test_helpers.c          # Helper function tests
```

### 3. Update CMakeLists.txt

Add this file with your test executable(s):

```cmake
# tests/CMakeLists.txt
find_package(Check REQUIRED)  # Or your chosen framework

add_executable(test_auth test_auth.c)
target_link_libraries(test_auth PRIVATE Check::check)
add_test(NAME AuthTests COMMAND test_auth)

# Add more test executables as needed
```

### 4. Enable in root CMakeLists.txt

Uncomment this line in the root `CMakeLists.txt`:
```cmake
add_subdirectory(tests)
```

### 5. Run tests

```bash
cmake -B build -DENABLE_TESTING=ON
cmake --build build
cd build && ctest --output-on-failure
```

## CI Integration

The CI pipeline is already configured to run `ctest`. Once you add tests:
- Tests run automatically on every push/PR
- Coverage reports are generated (when `ENABLE_COVERAGE=ON`)
- Sanitizer builds catch memory issues
- Test results appear in the GitHub Actions UI

## Test Guidelines

- Keep tests focused and independent
- Test one thing per test case
- Use descriptive test names
- Clean up resources in teardown
- Mock external dependencies when needed
- Aim for high coverage of critical paths (auth, ACLs, deduplication)
