#import "AppDelegate.h"
#import "MainController.h"
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

@implementation AmethystConfig
- (id)init {
    self = [super init];
    return self;
}

- (void)loadConfig {
    uint32_t cpu = 0;
    size_t size = sizeof(cpu);
    sysctlbyname("hw.cpufamily", &cpu, &size, NULL, 0);
    
    self.trigonSupported = !(cpu == CPUFAMILY_ARM_VORTEX_TEMPEST || cpu == CPUFAMILY_ARM_LIGHTNING_THUNDER);
    self.defaults = [NSUserDefaults standardUserDefaults];
    
    if ([self.defaults objectForKey:@"init"] == NULL) {
        NSDictionary *dict = [self.defaults dictionaryRepresentation];
        for (NSString *key in dict) [self.defaults removeObjectForKey:key];
        
        self.themeName = @"Amethyst";
        self.generator = @"0x1111111111111111";
        self.exploit = self.trigonSupported ? Exploit_Trigon : Exploit_Hemlock;
        self.enableTweaks = true;
        self.lightMode = true;

        [self.defaults setObject:self.themeName forKey:@"themeName"];
        [self.defaults setObject:self.generator forKey:@"generator"];
        [self.defaults setInteger:self.exploit forKey:@"exploit"];
        [self.defaults setBool:self.enableTweaks forKey:@"enableTweaks"];
        [self.defaults setBool:YES forKey:@"init"];
    } else {
        if ((self.themeName = [self.defaults stringForKey:@"themeName"]) == NULL) self.themeName = @"Amethyst";
        if ((self.generator = [self.defaults stringForKey:@"generator"]) == NULL) self.generator = @"0x1111111111111111";
        self.enableTweaks = [self.defaults boolForKey:@"enableTweaks"];
        self.lightMode = [self.defaults boolForKey:@"lightMode"];
        
        self.exploit = [self.defaults integerForKey:@"exploit"];
        if (self.exploit == Exploit_Trigon && !self.trigonSupported) {
            self.exploit = Exploit_Hemlock;
            [self.defaults setInteger:self.exploit forKey:@"exploit"];
        }
    }
    
    [self.defaults synchronize];
    NSString *docs_dir = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory,NSUserDomainMask, YES) objectAtIndex:0];
    self.trigonCachePath = [docs_dir stringByAppendingPathComponent:@"trigon.plist"];
    
    int fd = open([self.trigonCachePath UTF8String], O_RDONLY);
    if (fd >= 0) {
        size_t size = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        
        void *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
        
        if (data != MAP_FAILED) {
            CFDataRef cf_data = CFDataCreateWithBytesNoCopy(NULL, data, size, NULL);
            self.trigonCache = (CFMutableDictionaryRef)CFPropertyListCreateWithData(NULL, cf_data, kCFPropertyListMutableContainersAndLeaves, NULL, NULL);
            munmap(data, size);
        }
    }
    
    if (self.trigonCache == NULL) {
        self.trigonCache = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    }
}

- (void)saveConfig {
    [self.defaults setObject:self.themeName forKey:@"themeName"];
    [self.defaults setObject:self.generator forKey:@"generator"];
    [self.defaults setInteger:self.exploit forKey:@"exploit"];
    [self.defaults setBool:self.enableTweaks forKey:@"enableTweaks"];
    [self.defaults setBool:self.lightMode forKey:@"lightMode"];
    [self.defaults setBool:YES forKey:@"init"];
    [self.defaults synchronize];
}

- (NSString *)exploitString {
    switch (self.exploit) {
        case Exploit_Hemlock: return @"Hemlock";
        case Exploit_Trigon: return @"Trigon";
        default: return @"Unknown";
    }
}
@end

AmethystConfig *amethyst = NULL;

@interface AppDelegate ()
@end

@implementation AppDelegate
@synthesize window = _window;

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
    return ([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad);
}

- (UIInterfaceOrientationMask)application:(UIApplication *)application supportedInterfaceOrientationsForWindow:(UIWindow *)window {
    if (([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad)) {
        return UIInterfaceOrientationMaskAllButUpsideDown;
    }
    return UIInterfaceOrientationMaskPortrait;
}

- (UIInterfaceOrientationMask)supportedInterfaceOrientations{
    if (([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad)) {
        return UIInterfaceOrientationMaskAllButUpsideDown;
    }
    return UIInterfaceOrientationMaskPortrait;
}

- (BOOL)shouldAutorotate {
    return ([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad);
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    amethyst = [[AmethystConfig alloc] init];
    [amethyst loadConfig];
    
    [[UIApplication sharedApplication] setStatusBarOrientation:UIInterfaceOrientationPortrait animated:YES];
    _window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].fixedCoordinateSpace.bounds];
    _window.rootViewController = [[MainController alloc] init];
    [_window makeKeyAndVisible];
    return YES;
}
@end

uint64_t trigon_cache_get_u64(char *key) {
    if (key == NULL) return 0;
    NSString *key_str = [NSString stringWithUTF8String:key];
    if (key_str == NULL) return 0;
    
    NSString *value = [(__bridge NSDictionary *)amethyst.trigonCache valueForKey:key_str];
    if (value == NULL) return 0;
    
    char *value_str = (char *)[value UTF8String];
    if (value_str == NULL) return 0;
    
    if (strlen(value_str) >= 3 && value_str[0] == '0' && value_str[1] == 'x') {
        return (uint64_t)strtoull(value_str, NULL, 16);
    } else {
        return (uint64_t)strtoull(value_str, NULL, 10);
    }
}

int trigon_cache_set_u64(char *key, uint64_t value) {
    if (key == NULL) return -1;
    NSString *key_str = [NSString stringWithUTF8String:key];
    if (key_str == NULL) return -1;
    
    NSString *value_str = [NSString stringWithFormat:@"0x%llx", value];
    if (value_str == NULL) return -1;
    
    [(__bridge NSDictionary *)amethyst.trigonCache setValue:value_str forKey:key_str];
    return 0;
}

bool trigon_cache_get_bool(char *key) {
    if (key == NULL) return false;
    NSString *key_str = [NSString stringWithUTF8String:key];
    if (key_str == NULL) return false;
    return [[(__bridge NSDictionary *)amethyst.trigonCache valueForKey:key_str] isEqual: @"true"];
}

int trigon_cache_set_bool(char *key, bool value) {
    if (key == NULL) return -1;
    NSString *key_str = [NSString stringWithUTF8String:key];
    if (key_str == NULL) return -1;

    [(__bridge NSDictionary *)amethyst.trigonCache setValue:(value ? @"true" : @"false") forKey:key_str];
    return 0;
}

void trigon_cache_sync(void) {
    usleep(10000);
    CFDataRef data = CFPropertyListCreateData(NULL, amethyst.trigonCache, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
    if (data == NULL) return;;
    
    unlink([amethyst.trigonCachePath UTF8String]);
    FILE *file = fopen([amethyst.trigonCachePath UTF8String], "wb+");
    if (file == NULL) {
        CFRelease(data);
        return;
    }
    
    fwrite(CFDataGetBytePtr(data), CFDataGetLength(data), 1, file);
    fflush(file);
    fcntl(file->_file, F_FULLFSYNC, 0);
    
    fclose(file);
    CFRelease(data);
    sync();
}
