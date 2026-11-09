"""PHK1-safe runtime choice. PHK2 stays opt-in until a physical image is qualified."""
def select_backend(*, phk2_image_qualified:bool, phk2_host_qualified:bool=True)->str:
    return 'PHK2' if phk2_image_qualified and phk2_host_qualified else 'PHK1'
def rollback_backend()->str:
    return 'PHK1'
