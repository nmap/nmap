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

// Log and handle error
void handleError(NSDictionary *error, NSString *privilegeType) {
    NSLog(@"Failed to execute script with %@ privileges: %@", privilegeType, error[NSAppleScriptErrorBriefMessage]);
}

// Executes a script
BOOL executeScript(NSString *script, NSString *privilegeType) {
    NSDictionary *error;
    NSAppleScript *appleScript = [[NSAppleScript alloc] initWithSource:script];
    
    if ([appleScript executeAndReturnError:&error]) {
        NSLog(@"Executed script with %@ privileges successfully.", privilegeType);
        return YES;
    } else {
        handleError(error, privilegeType);
        return NO;
    }
}

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSString *cwd = [[NSBundle mainBundle] bundlePath];
        NSString *executableName = @"zenmap.bin"; // Consider making this configurable
        NSString *executablePath = [NSString stringWithFormat:@"%@/Contents/MacOS/%@", cwd, executableName];
        
        NSString *privilegedScript = [NSString stringWithFormat:@"do shell script \"%@\" with administrator privileges", executablePath];
        
        if (!executeScript(privilegedScript, @"administrator")) {
            NSString *unprivilegedScript = [NSString stringWithFormat:@"do shell script \"%@\"", executablePath];
            executeScript(unprivilegedScript, @"normal");
        }
    }
    return 0;
}
