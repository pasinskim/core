#include <test.h>

#include <eval_context.h>
#include <string_lib.h>

static
EvalContext *make_mock_eval_context()
{
     EvalContext *ctx = EvalContextNew();
     return ctx;
}

static
PackageManagerBody *make_mock_package_manager(const char *name, int updates_ifel, int installed_ifel, Rlist *options)
{
    PackageManagerBody *pm = xmalloc(sizeof(pm));
    pm->name = SafeStringDuplicate(name);
    pm->installed_ifelapesed = installed_ifel;
    pm->updates_ifelapsed = updates_ifel;
    pm->options = RlistCopy(options);
    return pm;
}

void tests_setup(void)
{
    static char env[] = /* Needs to be static for putenv() */
        "CFENGINE_TEST_OVERRIDE_WORKDIR=/tmp/CFENGINE_eval_context_test.XXXXXX";
    char *workdir = strchr(env, '=');
    assert(workdir && workdir[1] == '/');
    workdir++;

    mkdtemp(workdir);
    strlcpy(CFWORKDIR, workdir, CF_BUFSIZE);
    putenv(env);

    char state_dir[PATH_MAX];
    xsnprintf(state_dir, PATH_MAX, "%s/state", workdir);
    mkdir(state_dir, 0766);
}

void tests_teardown(void)
{
    char cmd[CF_BUFSIZE];
    xsnprintf(cmd, CF_BUFSIZE, "rm -rf '%s'", CFWORKDIR);
    system(cmd);
}

static void test_add_manager_to_context()
{
    EvalContext *ctx = make_mock_eval_context();

    PackageManagerBody *pm = make_mock_package_manager("apt_get", 120, 240, NULL);
    AddManagerToPackagePromiseContext(ctx, pm);
   
    PackageManagerBody *pm2 = make_mock_package_manager("yum", 220, 440, NULL);
    AddManagerToPackagePromiseContext(ctx, pm2);

    PackagePromiseContext *pp_ctx = GetPackagePromiseContext(ctx);

    assert_true(pp_ctx != NULL);
    assert_int_equal(2, SeqLength(pp_ctx->package_managers_bodies));

    PackageManagerBody *yum = GetManagerFromPackagePromiseContext(ctx, "yum");
    assert_true(yum != NULL);
    assert_int_equal(220, yum->updates_ifelapsed);
    assert_int_equal(440, yum->installed_ifelapesed);

    /* make sure that adding body with the same name will not make set larger */
    PackageManagerBody *pm3 = make_mock_package_manager("yum", 330, 550, NULL);
    AddManagerToPackagePromiseContext(ctx, pm3);

    assert_int_equal(2, SeqLength(pp_ctx->package_managers_bodies));

    /* check if parameters are updated */
    yum = GetManagerFromPackagePromiseContext(ctx, "yum");
    assert_int_equal(330, yum->updates_ifelapsed);
    assert_int_equal(550, yum->installed_ifelapesed);

    EvalContextDestroy(ctx);
}

static void test_default_package_manager_settings()
{
    EvalContext *ctx = make_mock_eval_context();

    PackageManagerBody *pm = make_mock_package_manager("apt_get", 120, 240, NULL);
    AddManagerToPackagePromiseContext(ctx, pm);
   
    PackageManagerBody *pm2 = make_mock_package_manager("yum", 220, 440, NULL);
    AddManagerToPackagePromiseContext(ctx, pm2);
    
    PackageManagerBody *pm3 = make_mock_package_manager("yum_2", 220, 440, NULL);
    AddManagerToPackagePromiseContext(ctx, pm3);

    PackagePromiseAddDefaultPackageManager(ctx, "apt_get", false);
    PackageManagerBody *def_pm = GetDefaultManagerFromPackagePromiseContext(ctx);
    assert_string_equal("apt_get", def_pm->name);
    
    PackagePromiseAddDefaultPackageManager(ctx, "yum", false);
    def_pm = GetDefaultManagerFromPackagePromiseContext(ctx);
    assert_string_equal("yum", def_pm->name);
    
    PackagePromiseAddDefaultPackageManager(ctx, "yum_2", true);
    def_pm = GetDefaultManagerFromPackagePromiseContext(ctx);
    assert_string_equal("yum_2", def_pm->name);
    
    PackagePromiseAddDefaultPackageManager(ctx, "yum", true);
    def_pm = GetDefaultManagerFromPackagePromiseContext(ctx);
    assert_string_equal("yum", def_pm->name);
    
    PackagePromiseAddDefaultPackageManager(ctx, "apt_get", false);
    def_pm = GetDefaultManagerFromPackagePromiseContext(ctx);
    assert_string_equal("yum", def_pm->name);

    EvalContextDestroy(ctx);
}


int main()
{
    PRINT_TEST_BANNER();
    tests_setup();

    const UnitTest tests[] =
    {
        unit_test(test_add_manager_to_context),
        unit_test(test_default_package_manager_settings),
    };

    int ret = run_tests(tests);

    tests_teardown();

    return ret;
}
