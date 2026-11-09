from polarizer.compare import flatten, looks_like_same_object, similarity


def test_identical_objects_score_one():
    obj = {"id": 1, "name": "x", "nested": {"a": [1, 2]}}
    assert similarity(obj, obj) == 1.0


def test_unrelated_objects_score_low():
    assert similarity({"a": 1}, {"b": 2}) == 0.0


def test_same_object_detected_despite_a_small_difference():
    owner = {"id": 1, "customer": "Bakery", "amount": 1000, "status": "paid"}
    other = {"id": 1, "customer": "Bakery", "amount": 1000, "status": "sent"}
    assert looks_like_same_object(owner, other)


def test_none_is_never_the_same_object():
    assert similarity(None, {"a": 1}) == 0.0
    assert not looks_like_same_object(None, None)


def test_flatten_nests_keys():
    assert flatten({"a": {"b": 1}, "c": [2]}) == {"a.b": 1, "c.0": 2}
