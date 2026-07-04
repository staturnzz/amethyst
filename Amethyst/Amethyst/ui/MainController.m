#import <QuartzCore/QuartzCore.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreText/CoreText.h>
#import "../AppDelegate.h"
#import "MainController.h"
#import "../jailbreak/jailbreak.h"
#import <mach-o/dyld.h>

MainController *mainController = NULL;
void (^alertCallback)(void) = NULL;
extern int jbserver_heartbeat(void);
extern int sandbox_check(pid_t pid, const char *operation, uint32_t type, ...);
extern int csops(pid_t pid, unsigned int  ops, void *useraddr, size_t usersize);

@implementation MainController
- (bool)prefersStatusBarHidden {
    return self.hideStatusBar;
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

- (bool)deviceSupported {
    int version = [[[UIDevice currentDevice] systemVersion] intValue];
    return (version == 12 || version == 13);
}

- (bool)deviceJailbroken {
    if (self.isJailbroken == -1) {
        if (jbserver_heartbeat() == 0x1337 ||
            sandbox_check(getpid(), NULL, 0, NULL) == 0 ||
            access("/", R_OK | W_OK) == 0) {
            self.isJailbroken = 1;
            return true;
        }
        
        void *handle = dlopen("/usr/lib/libjailbreak.dylib", RTLD_NOW);
        if (handle != NULL) {
            void *fix_setuid = dlsym(handle, "jb_oneshot_fix_setuid_now");
            void *entitle_now = dlsym(handle, "jb_oneshot_entitle_now");
            
            dlclose(handle);
            if (fix_setuid != NULL || entitle_now != NULL) {
                self.isJailbroken = 1;
                return true;
            }
        }
        
        mach_port_t tfp0 = MACH_PORT_NULL;
        host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfp0);
        if (!MACH_PORT_VALID(tfp0)) task_for_pid(mach_task_self(), 0, &tfp0);
        
        if (MACH_PORT_VALID(tfp0)) {
            mach_port_deallocate(mach_task_self(), tfp0);
            self.isJailbroken = 1;
            return true;
        }
        
        uint32_t cs_flags = 0;
        if (csops(getpid(), 0, &cs_flags, 4) == 0) {
            if (cs_flags & 0x04000000) {
                self.isJailbroken = 1;
                return true;
            }
        }
        
        uint32_t image_count = _dyld_image_count();
        for (int i = 0; i < image_count; i++) {
            const char *name = _dyld_get_image_name(i);
            if (strcmp(name, "/usr/lib/base_hook.dylib") == 0 ||
                strcmp(name, "/usr/lib/pspawn_payload.dylib") == 0 ||
                strcmp(name, "/usr/lib/pspawn_payload-stg2.dylib") == 0) {
                self.isJailbroken = 1;
                return true;
            }
        }
        
        self.isJailbroken = 0;
        return false;
    }
    return (self.isJailbroken == 1);
}

- (void)setBackgroundImage:(NSString *)image_name {
    CGRect frame = self.view.bounds;
    if (([UIDevice currentDevice].userInterfaceIdiom == UIUserInterfaceIdiomPad)) {
        UIInterfaceOrientation orientation = [[UIApplication sharedApplication] statusBarOrientation];
        
        if (!UIInterfaceOrientationIsLandscape(orientation)) {
            CGFloat old_width = frame.size.width;
            CGFloat old_height = frame.size.height;
            frame.size.width = old_height;
            frame.size.height = old_width;
        }
    }

    frame.size.width += 80;
    frame.size.height += 80;
    frame.origin.x -= 40;
    frame.origin.y -= 40;
    
    self.bgImage = [[UIImageView alloc] initWithFrame:frame];
    self.bgImage.image = [UIImage imageNamed:image_name];
    self.bgImage.contentMode = UIViewContentModeScaleAspectFill;
    self.bgImage.backgroundColor = [UIColor clearColor];
    [self.view addSubview:self.bgImage];
    [self.view sendSubviewToBack:self.bgImage];
}

- (void)changeBackgroundImage:(NSString *)image_name {
    amethyst.themeName = image_name;
    [amethyst saveConfig];
    [self.themeOption.optionButton setTitle:amethyst.themeName forState:UIControlStateNormal];

    UIView *currentBackground = self.view.subviews.firstObject;
    [self setBackgroundImage:[NSString stringWithFormat:@"bg_%@", amethyst.themeName]];
    
    [UIView animateWithDuration:1.0 animations:^{
        currentBackground.alpha = 0.0;
    } completion:^(BOOL finished) {
        if (finished) [currentBackground removeFromSuperview];
    }];
}

- (void)toggleLightMode {
    if (amethyst.lightMode) {
        amethyst.lightMode = false;
        [self.lightModeOption.optionButton setTitle:@"Light Mode" forState:UIControlStateNormal];
    } else {
        amethyst.lightMode = true;
        [self.lightModeOption.optionButton setTitle:@"Dark Mode" forState:UIControlStateNormal];
    }
    
    [amethyst saveConfig];
    [self.mainCard toggleLightMode];
    [self.settingsPopupCard toggleLightMode];
    [self.creditsPopupCard toggleLightMode];
    [self.themePopupCard toggleLightMode];
    [self.generatorPopupCard toggleLightMode];
    [self.exploitPopupCard toggleLightMode];
    [self.alert toggleLightMode];
}

- (void)loadView {
    [super loadView];
    mainController = self;
    self.hideStatusBar = false;
    self.isJailbroken = -1;
    [self setNeedsStatusBarAppearanceUpdate];

    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(logProgress:) name:@"status" object:nil];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(fadeDisplay:) name:@"fade" object:nil];

    [self setBackgroundImage:[NSString stringWithFormat:@"bg_%@", amethyst.themeName]];
    if ([UIScreen mainScreen].bounds.size.width == 320.0f) {
        amethyst.buttonCardWidth = 280.0f;
        amethyst.popupCardWidth = 280.0f;
        amethyst.popupCardHeight = 480.0f;
    } else {
        amethyst.buttonCardWidth = 320.0f;
        amethyst.popupCardWidth = 300.0f;
        amethyst.popupCardHeight = 540.0f;
    }
    
    initSubview(titleIcon, [UIImageView createImage:@"glyph" alpha:0.6f]);
    initSubview(mainTitle, [UILabel createLabel:@"Amethyst" size:56.0f bold:YES align:NSTextAlignmentCenter]);
    initSubview(mainSubtitle, [UILabel createLabel:@"iOS 12-13 jailbreak by @staturnzdev" size:12 bold:NO align:NSTextAlignmentCenter]);
    
    [self.mainTitle addShadowWithRadius:10.0f opacity:0.3f offset:CGSizeMake(0.0f, 0.2f)];
    [self.mainSubtitle addShadowWithRadius:4.0f opacity:0.2f offset:CGSizeMake(0.0f, 0.2f)];
    self.mainTitle.alpha = 0.9f;
    self.mainSubtitle.alpha = 0.8f;

    self.mainCard = [[CardView alloc] initWithViews:@[
        initCardBtnOption(jailbreakCardButton, @"Jailbreak", jailbreakButtonAction),
        initCardBtnOption(creditsCardButton, @"Credits", openCreditsCard),
        initCardBtnOption(settingsCardButton, @"Settings", openSettingsCard)
    ]];
    
    self.mainCard.cardView.alpha = 0.95f;
    self.bgImage.alpha = 0.85f;
    [self.settingsCardButton showSeprator:NO];
    [self.view addSubview:self.mainCard.cardView];

    self.progressRing = [[ProgressRing alloc] initWithFrame:CGRectMake(0, 0, 200, 200)];
    [self.view addSubview:self.progressRing];
    
    self.blurOverlay = [[UIVisualEffectView alloc] initWithEffect:[UIBlurEffect effectWithStyle:UIBlurEffectStyleDark]];
    self.blurOverlay.translatesAutoresizingMaskIntoConstraints = NO;
    self.blurOverlay.alpha = 0.0;
    [self.view addSubview:self.blurOverlay];

    self.gestureOverlay = [[UIView alloc] init];
    [self.gestureOverlay addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(closeAllCards:)]];
    self.gestureOverlay.translatesAutoresizingMaskIntoConstraints = NO;
    self.gestureOverlay.backgroundColor = [UIColor clearColor];
    self.gestureOverlay.userInteractionEnabled = NO;
    self.gestureOverlay.frame = self.view.frame;
    [self.view addSubview:self.gestureOverlay];
    
    self.alertOverlay = [[UIView alloc] init];
    self.alertOverlay.translatesAutoresizingMaskIntoConstraints = NO;
    self.alertOverlay.backgroundColor = [UIColor blackColor];
    self.alertOverlay.userInteractionEnabled = NO;
    self.alertOverlay.frame = self.view.frame;
    self.alertOverlay.alpha = 0.0f;
    [self.view addSubview:self.alertOverlay];

    if (![self deviceSupported]) {
        [self.jailbreakCardButton setTitle:@"Unsupported"];
        self.jailbreakCardButton.optionButton.alpha = 0.6f;
        self.jailbreakCardButton.optionButton.enabled = NO;
        [self.progressRing setProgressPercent:0 label:@"Unsupported"];
    } else if ([self deviceJailbroken]) {
        [self.jailbreakCardButton setTitle:@"Jailbroken"];
        self.jailbreakCardButton.optionButton.alpha = 0.6f;
        self.jailbreakCardButton.optionButton.enabled = NO;
        [self.progressRing setProgressPercent:0 label:@"Jailbroken"];
    }
    
    self.creditsPopupCard = [[PopupCard alloc] init:@"Credits" withViews:@[
        initOtherOption(creditsTable, [[CreditsController alloc] init]).tableView,
    ]];

    self.themePopupCard = [[PopupCard alloc] init:@"Theme" withViews:@[
        initFullBtnOption(lightModeOption, @"Light Mode", toggleLightMode),
        initImgBtnOption(themeOption1, @"bg_Amethyst", applyTheme1),
        initImgBtnOption(themeOption2, @"bg_Citrus", applyTheme2),
        initImgBtnOption(themeOption3, @"bg_Dusk", applyTheme3),
        initImgBtnOption(themeOption4, @"bg_Oxide", applyTheme4),
    ]];
    
    self.generatorPopupCard = [[PopupCard alloc] init:@"Generator" withViews:@[
        initFullBtnOption(saveGeneratorOption, @"Save", saveGenerator),
        initTextFieldOption(generatorTextField, amethyst.generator, monitorGeneratorText:)
    ]];

    self.exploitPopupCard = [[PopupCard alloc] init:@"Exploit" withViews:@[
        initFullBtnOption(exploitOptionHemlock, @"Hemlock", setExploitHemlock),
        initFullBtnOption(exploitOptionTrigon, @"Trigon", setExploitTrigon),
    ]];
    
    if (!amethyst.trigonSupported) {
        self.exploitOptionTrigon.optionButton.enabled = false;
        self.exploitOptionTrigon.optionView.alpha = 0.5f;
    }
    
    NSString *version = [NSString stringWithFormat:@"version %@", [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleShortVersionString"]];
    self.settingsPopupCard = [[PopupCard alloc] init:@"Settings" withViews:@[
        initSwitchOption(enableTweaksOption, @"Enable Tweaks"),
        initSwitchOption(restoreRootFSOption, @"Restore RootFS"),
        initBtnOption(exploitOption, @"Exploit", [amethyst exploitString], exploitButtonAction),
        initBtnOption(setGeneratorOption, @"Generator", amethyst.generator, setGenerator),
        initBtnOption(themeOption, @"Theme", amethyst.themeName, selectTheme),
        initOtherOption(versionLabel, [UILabel createLabel:version size:12 bold:0 align:NSTextAlignmentCenter]),
        initOtherOption(versionIcon, [UIImageView createImage:@"glyph" alpha:0.6f]),
    ]];

    finalizePopupCard(creditsPopupCard);
    finalizePopupCard(themePopupCard);
    finalizePopupCard(generatorPopupCard);
    finalizePopupCard(exploitPopupCard);
    finalizePopupCard(settingsPopupCard);
    
    [self.enableTweaksOption setSwitchCallback:self _sel:@selector(enableTweaksHandler:)];
    self.installAlert = [[InstallAlert alloc] init];
    [self.view addSubview:self.installAlert.alertView];
    [self.installAlert setOverlay:self.alertOverlay];
    

    self.alert = [[PopupAlert alloc] init:@"" message:@"" button:@"" _id:self _sel:@selector(alertHandler)];
    [self.view addSubview:self.alert.alertView];
    [self.alert setOverlay:self.alertOverlay];
    
    [self.enableTweaksOption setSwitchValue:amethyst.enableTweaks];
    [self.themeOption showSeprator:NO];
    self.versionLabel.alpha = 0.60f;
    if (amethyst.lightMode) {
        [self.lightModeOption.optionButton setTitle:@"Dark Mode" forState:UIControlStateNormal];
    }
    [self applyConstraints];
}

- (NSString *)getErrorTitle:(jb_error_t)err {
    switch (err) {
        case JB_ERROR_SUCCESS: return @"Jailbreak Done";
        case JB_ERROR_REMOUNT_REBOOT: return @"Reboot Required";
        case JB_ERROR_RESTORE_REBOOT: return @"Reboot Required";
        case JB_ERROR_RESTORE: return @"Restore Failed";
        case JB_ERROR_OTA: return @"Unable to Continue";
        case JB_ERROR_UNSUPPORTED_INSTALL: return @"Restore RootFS Required";
        default: return @"Jailbreak Failed";
    }
}

- (NSString *)getErrorButton:(jb_error_t)err {
    switch (err) {
        case JB_ERROR_REMOUNT_REBOOT: return @"Reboot";
        case JB_ERROR_RESTORE_REBOOT: return @"Reboot";
        default: return @"Okay";
    }
}

- (NSString *)getErrorMessage:(jb_error_t)err {
    switch (err) {
        case JB_ERROR_SUCCESS: return @"Jailbreak Done";
        case JB_ERROR_EXPLOIT: return @"Kernel exploit failed. Reboot the device before attempting to jailbreak again.";
        case JB_ERROR_PERMISSION: return @"Failed to initialize permissions.";
        case JB_ERROR_PATCHFINDER: return @"Failed to find required system patches and offsets";
        case JB_ERROR_TRUSTCACHE: return @"Failed to initialize trustcache.";
        case JB_ERROR_PPL: return @"Failed to initialize the PPL bypass.";
        case JB_ERROR_REMOUNT: return @"Failed to remount RootFS.";
        case JB_ERROR_RESTORE: return @"Failed to restore RootFS.";
        case JB_ERROR_OTA: return @"OTA Update file is already mounted. Delete the update before attempting to jailbreak again.";
        case JB_ERROR_REMOUNT_REBOOT: return @"A reboot is required to continue with the jailbreak process. After the device reboots, run the jailbreak again.";
        case JB_ERROR_RESTORE_REBOOT: return @"A reboot is required to complete the RootFS restore.";
        case JB_ERROR_HANDOFF: return @"Failed to handoff the jailbreak server to launchd.";
        case JB_ERROR_DYLD: return @"Failed to apply patches to dyld.";
        case JB_ERROR_BOOTSTRAP: return @"Failed to install bootstrap.";
        case JB_ERROR_SILEO: return @"Failed to install Sileo.";
        case JB_ERROR_ZEBRA: return @"Failed to install Zebra.";
        case JB_ERROR_LIBSWIFT: return @"Failed to install libswift.";
        case JB_ERROR_UNSUPPORTED_INSTALL: return @"An unsupported jailbreak is currently installed on this device. Restore RootFS before attempting to jailbreak again.";
        default: return @"An unknown error has occurred";
    }
}

- (void)applyConstraints {
    self.layoutGuide = self.view.safeAreaLayoutGuide;
    CGFloat versionOffset = ([UIScreen mainScreen].bounds.size.width == 320.0f) ? -15.0f : -30.0f;

    [NSLayoutConstraint activateConstraints:@[
        fillScreenConstraint(blurOverlay),
        fillScreenConstraint(gestureOverlay),
        fillScreenConstraint(alertOverlay),
        popupCardConstraint(creditsPopupCard, amethyst.popupCardWidth, amethyst.popupCardHeight),
        popupCardConstraint(settingsPopupCard, amethyst.popupCardWidth, amethyst.popupCardHeight),
        popupAlertConstraint(alert),
        popupAlertConstraint(installAlert),
        popupCardConstraint(themePopupCard, 280.0f, 380.0f),
        popupCardConstraint(generatorPopupCard, 280.0f, 200.0f),
        popupCardConstraint(exploitPopupCard, 280.0f, 200.0f),
        setAnchorConstraint(themeOption1.optionView.topAnchor, themePopupCard.separator.bottomAnchor, 30.0f),
        setAnchorConstraint(themeOption1.optionView.leadingAnchor, themePopupCard.cardView.leadingAnchor, 40.0f),
        setAnchorConstraint(themeOption2.optionView.topAnchor, themePopupCard.separator.bottomAnchor, 30.0f),
        setAnchorConstraint(themeOption2.optionView.leadingAnchor, themeOption1.optionView.trailingAnchor, 40.0f),
        setAnchorConstraint(themeOption3.optionView.topAnchor, themeOption1.optionView.bottomAnchor, 30.0f),
        setAnchorConstraint(themeOption3.optionView.leadingAnchor, themePopupCard.cardView.leadingAnchor, 40.0f),
        setAnchorConstraint(themeOption4.optionView.topAnchor, themeOption2.optionView.bottomAnchor, 30.0f),
        setAnchorConstraint(themeOption4.optionView.leadingAnchor, themeOption3.optionView.trailingAnchor, 40.0f),
        setAnchorConstraint(lightModeOption.optionView.leadingAnchor, themePopupCard.cardView.leadingAnchor, 40.0f),
        setAnchorConstraint(lightModeOption.optionView.trailingAnchor, themePopupCard.cardView.trailingAnchor, -40.0f),
        setAnchorConstraint(lightModeOption.optionView.topAnchor, themeOption4.optionView.bottomAnchor, 20.0),
        setAnchorConstraint(generatorTextField.topAnchor, generatorPopupCard.separator.bottomAnchor, 20.0f),
        setAnchorConstraint(generatorTextField.centerXAnchor, view.centerXAnchor, 0.0f),
        setAnchorConstraint(generatorTextField.widthAnchor, generatorPopupCard.cardView.widthAnchor, -40.0f),
        setConstantConstraint(generatorTextField.heightAnchor, 40.0f),
        setAnchorConstraint(saveGeneratorOption.optionView.topAnchor, generatorTextField.bottomAnchor, 20.0f),
        setAnchorConstraint(saveGeneratorOption.optionView.centerXAnchor, view.centerXAnchor, 0.0f),
        setAnchorConstraint(saveGeneratorOption.optionView.widthAnchor, generatorPopupCard.cardView.widthAnchor, -40.0f),
        setConstantConstraint(saveGeneratorOption.optionView.heightAnchor, 40.0f),
        exploitButtonConstraint(exploitOptionHemlock, exploitPopupCard.separator),
        exploitButtonConstraint(exploitOptionTrigon, exploitOptionHemlock.optionView),
        mainCardOptionConstraint(jailbreakCardButton, mainCard.cardView, 5),
        mainCardOptionConstraint(creditsCardButton, jailbreakCardButton.separator, 0),
        mainCardOptionConstraint(settingsCardButton, creditsCardButton.separator, 0),
        settingsOptionConstraint(enableTweaksOption, settingsPopupCard.cardTitle),
        settingsOptionConstraint(restoreRootFSOption, enableTweaksOption.optionView),
        settingsOptionConstraint(exploitOption, restoreRootFSOption.optionView),
        settingsOptionConstraint(setGeneratorOption, exploitOption.optionView),
        settingsOptionConstraint(themeOption, setGeneratorOption.optionView),
        setAnchorConstraint(creditsTable.view.topAnchor, creditsPopupCard.separator.bottomAnchor, 0),
        setAnchorConstraint(creditsTable.view.leadingAnchor, creditsPopupCard.cardView.leadingAnchor, 5),
        setAnchorConstraint(creditsTable.view.trailingAnchor, creditsPopupCard.cardView.trailingAnchor, -5),
        setAnchorConstraint(creditsTable.view.bottomAnchor, creditsPopupCard.cardView.bottomAnchor, 0),
        setAnchorConstraint(mainCard.cardView.centerXAnchor, view.centerXAnchor, 0),
        setAnchorConstraint(mainCard.cardView.bottomAnchor, layoutGuide.bottomAnchor, -30),
        setConstantConstraint(mainCard.cardView.widthAnchor, amethyst.buttonCardWidth),
        setConstantConstraint(mainCard.cardView.heightAnchor, 170),
        setAnchorConstraint(mainTitle.topAnchor, layoutGuide.topAnchor, 40),
        setAnchorConstraint(mainTitle.centerXAnchor, view.centerXAnchor, 0),
        setAnchorConstraint(mainSubtitle.topAnchor, mainTitle.bottomAnchor, 3),
        setAnchorConstraint(mainSubtitle.centerXAnchor, view.centerXAnchor, 0),
        setAnchorConstraint(progressRing.centerXAnchor, view.centerXAnchor, 0),
        setAnchorConstraint(progressRing.centerYAnchor, view.centerYAnchor, -30),
        setConstantConstraint(progressRing.widthAnchor, 180),
        setConstantConstraint(progressRing.heightAnchor, 180),
        setAnchorConstraint(versionLabel.bottomAnchor, settingsPopupCard.cardView.bottomAnchor, versionOffset),
        setAnchorConstraint(versionLabel.centerXAnchor, settingsPopupCard.cardView.centerXAnchor, 0),
        setAnchorConstraint(versionIcon.bottomAnchor, versionLabel.topAnchor, -5),
        setAnchorConstraint(versionIcon.centerXAnchor, settingsPopupCard.cardView.centerXAnchor, 0),
        setConstantConstraint(versionIcon.widthAnchor, 30),
        setConstantConstraint(versionIcon.heightAnchor, 30),
        setAnchorConstraint(titleIcon.bottomAnchor, mainTitle.topAnchor, 0),
        setAnchorConstraint(titleIcon.centerXAnchor, settingsPopupCard.cardView.centerXAnchor, 0),
        setConstantConstraint(titleIcon.widthAnchor, 30),
        setConstantConstraint(titleIcon.heightAnchor, 30)
    ]];
    
    self.creditsTable.tableView.frame = self.creditsPopupCard.cardView.frame;
}

- (void)jailbreakButtonAction {
    [self.progressRing showRing];
    self.jailbreakCardButton.optionButton.enabled = false;
    self.creditsCardButton.optionButton.enabled = false;
    self.settingsCardButton.optionButton.enabled = false;
    [self.jailbreakCardButton.optionButton setTitleColor:[UIColor clearColor] forState:UIControlStateNormal];

    amethyst.restoreRootfs = [self.restoreRootFSOption getSwitchValue];
    amethyst.enableTweaks = [self.enableTweaksOption getSwitchValue];
    uint32_t flags = JB_FLAG_NONE;
    
    if (amethyst.restoreRootfs) flags |= JB_FLAG_RESTORE_ROOTFS;
    if (amethyst.enableTweaks) flags |= JB_FLAG_ENABLE_TWEAKS;
    if (amethyst.exploit == Exploit_Hemlock) {
        flags |= JB_FLAG_EXPLOIT_HEMLOCK;
    } else {
        flags |= JB_FLAG_EXPLOIT_TRIGON;
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        jb_error_t err = run_jailbreak(flags, (char *)[amethyst.generator UTF8String]);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.jailbreakCardButton.optionButton.enabled = true;
            self.creditsCardButton.optionButton.enabled = true;
            self.settingsCardButton.optionButton.enabled = true;
            [self.jailbreakCardButton.optionButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
            
            alertCallback = ^(){};
            if (err == JB_ERROR_REMOUNT_REBOOT || err == JB_ERROR_RESTORE_REBOOT) {
                [self.progressRing hideRing];
                alertCallback = ^() {
                    dispatch_async(dispatch_get_main_queue(), ^{
                        self.hideStatusBar = true;
                        [self setNeedsStatusBarAppearanceUpdate];
                        
                        [UIView animateWithDuration:0.5 delay:0.0 options:UIViewAnimationOptionCurveEaseInOut animations: ^{
                            mainController.blurOverlay.alpha = 1.0;
                            mainController.blurOverlay.backgroundColor = [UIColor blackColor];
                            mainController.blurOverlay.effect = NULL;
                        } completion: ^(BOOL finished) {
                            if (finished) {
                                reboot(0);
                                for (uint32_t i = 0; i < 10; i++) {
                                    usleep(100000);
                                    sync();
                                }
                            }
                        }];
                    });
                };
            } else if (err != JB_ERROR_SUCCESS) {
                [self.progressRing setProgressPercent:1.0f label:@"Failed"];
            }
            
            if (err != JB_ERROR_SUCCESS) {
                [self.alert setText:[self getErrorTitle:err] message:[self getErrorMessage:err] button:[self getErrorButton:err]];
                [self.alert setAction:self _sel:@selector(alertHandler)];
                [self.alert openAlert];
            }
        });
    });
}

- (void)closeAllCards:(UITapGestureRecognizer *)recognizer {
    if ([self.creditsPopupCard isOpen]) {
        [self.creditsPopupCard closeCard];
    } else if ([self.themePopupCard isOpen]) {
        [self.themePopupCard switchToCard:self.settingsPopupCard];
        self.themeOption.optionButton.titleLabel.text = amethyst.themeName;
    } else if ([self.exploitPopupCard isOpen]) {
        [self.exploitPopupCard switchToCard:self.settingsPopupCard];
    } else if ([self.generatorPopupCard isOpen]) {
        [[UIApplication sharedApplication] sendAction:@selector(resignFirstResponder) to:NULL from:NULL forEvent:NULL];
        self.generatorTextField.text = amethyst.generator;
        self.saveGeneratorOption.optionButton.enabled = YES;
        [self.saveGeneratorOption.optionButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        [self.generatorPopupCard switchToCard:self.settingsPopupCard];
    } else {
        [self.settingsPopupCard closeCard];
    }

    if ([self.restoreRootFSOption getSwitchValue]) {
        if (![self deviceJailbroken] && [self deviceSupported]) {
            [self.jailbreakCardButton setTitle:@"Restore RootFS"];
        } else {
            [self.restoreRootFSOption setSwitchValue:NO];
        }
    } else {
        if (![self deviceJailbroken]) {
            [self.jailbreakCardButton setTitle:@"Jailbreak"];
        }
        
        if (![self deviceSupported]) {
            [self.jailbreakCardButton setTitle:@"Unsupported"];
        }
    }
    
    amethyst.themeName = self.themeOption.optionButton.titleLabel.text;
    amethyst.enableTweaks = [self.enableTweaksOption getSwitchValue];
    [amethyst saveConfig];
}

- (void)monitorGeneratorText:(UITextField *)textField {
    if (textField.text.length > 18) [textField deleteBackward];
    const char *text = [textField.text UTF8String];
    UIColor *set_color = [UIColor whiteColor];
    bool set_enabled = true;

    if (text[0] == '0' || text[1] == 'x') {
        for (int i = 2; i < 18; i++) {
            if (!isxdigit(text[i])) {
                set_enabled = false;
                break;
            }
        }
    } else {
        set_enabled = false;
    }

    if (!set_enabled) set_color = [set_color colorWithAlphaComponent:0.4f];
    self.saveGeneratorOption.optionButton.enabled = set_enabled;
    [self.saveGeneratorOption.optionButton setTitleColor:set_color forState:UIControlStateNormal];
}

- (void)alertHandler {
    [self.alert closeAlert];
    if (alertCallback != NULL) {
        alertCallback();
        alertCallback = NULL;
    }
}

- (void)enableTweaksHandler:(UISwitch *)_switch {
    if ([self isJailbroken]) {
        if (_switch.isOn) {
            unlink("/amethyst/.disable_tweaks");
        } else {
            FILE *file = fopen("/amethyst/.disable_tweaks", "w+");
            fflush(file);
            fclose(file);
        }
        sync();
    }
}

- (void)selectTheme {[self.settingsPopupCard switchToCard:self.themePopupCard];}
- (void)setGenerator {[self.settingsPopupCard switchToCard:self.generatorPopupCard];}
- (void)openCreditsCard {[self.creditsPopupCard openCard];}
- (void)openSettingsCard {[self.settingsPopupCard openCard];}
- (void)exploitButtonAction {[self.settingsPopupCard switchToCard:self.exploitPopupCard];}
- (void)setExploitHemlock {[self changeExploit:Exploit_Hemlock];}
- (void)setExploitTrigon {[self changeExploit:Exploit_Trigon];}
- (void)applyTheme1 {[self changeBackgroundImage:@"Amethyst"];}
- (void)applyTheme2 {[self changeBackgroundImage:@"Citrus"];}
- (void)applyTheme3 {[self changeBackgroundImage:@"Dusk"];}
- (void)applyTheme4 {[self changeBackgroundImage:@"Oxide"];}

- (void)saveGenerator {
    amethyst.generator = self.generatorTextField.text;
    [self.setGeneratorOption.optionButton setTitle:amethyst.generator forState:UIControlStateNormal];
    [amethyst saveConfig];
    [self closeAllCards:NULL];
}

- (void)changeExploit:(AmethystExploitOption)exploitOption {
    amethyst.exploit = exploitOption;
    [self.exploitOption.optionButton setTitle:[amethyst exploitString] forState:UIControlStateNormal];
    [amethyst saveConfig];
    [self closeAllCards:NULL];
}

- (void)logProgress:(NSNotification *)noti {
    dispatch_async(dispatch_get_main_queue(), ^{
        CGFloat percent = ((NSNumber *)noti.userInfo[@"progress"][0]).floatValue;
        NSString *label = noti.userInfo[@"msg"][0];
        [self.progressRing setProgressPercent:percent label:label];
    });
}

- (void)fadeDisplay:(NSNotification *)noti {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.hideStatusBar = true;
        [self setNeedsStatusBarAppearanceUpdate];
        
        [UIView animateWithDuration:1.25 animations:^{
            mainController.blurOverlay.alpha = 1.0;
            mainController.blurOverlay.backgroundColor = [UIColor blackColor];
            mainController.blurOverlay.effect = NULL;
        }];
    });
}

- (void)sendPopupAlert:(NSString *)title message:(NSString *)message button:(NSString *)button {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.alert setText:title message:message button:button];
        [self.alert setAction:self _sel:@selector(alertHandler)];
        [self.alert openAlert];
    });
}
@end


void ProgressLog(float progress, const char *fmt, ...) {
    char buf[1024] = {0};
    va_list args = NULL;
    
    va_start(args, fmt);
    vsprintf(buf, fmt, args);
    va_end(args);
    
    NSDictionary* data = @{
        @"progress": @[[NSNumber numberWithFloat:progress]],
        @"msg": @[[NSString stringWithUTF8String:buf]]
    };
    [[NSNotificationCenter defaultCenter] postNotificationName:@"status" object:nil userInfo:data];
}

void FadeDisplay(void) {
    [[NSNotificationCenter defaultCenter] postNotificationName:@"fade" object:NULL userInfo:NULL];
}

void ShowAlert(const char *title, const char *msg, const char *btn, void (^action)(void)) {
    NSString *titleString = [NSString stringWithUTF8String:title];
    NSString *msgString = [NSString stringWithUTF8String:msg];
    NSString *btnString = [NSString stringWithUTF8String:btn];
    
    alertCallback = action;
    [mainController sendPopupAlert:titleString message:msgString button:btnString];
}

uint32_t get_install_options(void) {
    __block uint32_t flags = 0;
    dispatch_async(dispatch_get_main_queue(), ^{
        mainController.installAlert.alertView.alpha = 0.01;
        [mainController.installAlert openAlert];
    });
    
    while (!mainController.installAlert.selectionDone) {}
    dispatch_async(dispatch_get_main_queue(), ^{
        if ([mainController.installAlert.installSileo getSwitchValue]) flags |= JB_FLAG_INSTALL_SILEO;
        if ([mainController.installAlert.installZebra getSwitchValue]) flags |= JB_FLAG_INSTALL_ZEBRA;
    });
    
    usleep(10000);
    return flags;
}
