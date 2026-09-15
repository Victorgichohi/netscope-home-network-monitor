from app.services.enrichment import classify_destination, infer_device_category


def test_destination_service_classification():
    assert classify_destination("r3---sn.googlevideo.com") == ("Google / YouTube", "Streaming")
    assert classify_destination("192.168.1.10") == ("Local network", "Local")


def test_device_category_inference():
    assert infer_device_category("Living-Room-TV", "Samsung") == "media"
    assert infer_device_category("victors-iphone", "Apple") == "phone"
    assert infer_device_category(None, "Unknown") == "unknown"
