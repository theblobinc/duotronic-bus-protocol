from dbp3.profiles import UTM_PROFILE,WGRNN_PROFILE
def test_profile_bounds():
    assert UTM_PROFILE.max_records_per_frame <= 128; assert WGRNN_PROFILE.replay_window >= UTM_PROFILE.replay_window
