//
//  zenmap_auth.m
//  Objective-C
//
//  This program attempts to run an applescript script which asks for root
//  privileges. If the authorization fails or is canceled, Zenmap is run
//  without privileges using applescript.
//
//  This program is the first link in the chain:
//      zenmap_auth -> zenmap_wrapper.py -> zenmap.bin
//

#import <Foundation/Foundation.h>
#import <libgen.h>
#define EXECUTABLE_NAME "zenmap.bin"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *executable_path;
        NSString *cwd;
        size_t len_cwd;

        cwd = [[NSBundle mainBundle] bundlePath];
        len_cwd = [cwd length];
        executable_path = cwd;
        executable_path = [NSString stringWithFormat:@"%@/Contents/MacOS/%s", executable_path, EXECUTABLE_NAME];
        NSLog(@"%@",executable_path);

        NSDictionary *error = [NSDictionary new];
        NSString *script = [NSString stringWithFormat:@"do shell script \"%@\" with administrator privileges", executable_path];
NSLog(@"Executing: >>%@<<", script);
        NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:script];
        if ([appleScript executeAndReturnError:&error]) {
            NSLog(@"success!");
        } else {
            NSLog(@"Failed to execute applescript with admin privileges: %@", error[@"NSAppleScriptErrorMessage"]);
            NSDictionary *error = [NSDictionary new];
            NSString *script = [NSString stringWithFormat:@"do shell script \"%@\"", executable_path];
NSLog(@"Executing: >>%@<<", script);
            NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:script];
            if ([appleScript executeAndReturnError:&error]) {
                NSLog(@"success!");
            } else {
                NSLog(@"Failed to execute applescript: %@", error[@"NSAppleScriptErrorMessage"]);
            }
        }
    }
    return 0;
}
