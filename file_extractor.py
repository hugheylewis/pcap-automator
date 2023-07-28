import glob
import os
import hashlib


class Packet:
    def __init__(self, path):
        self._path = path

    @property
    def path(self):
        return self._path

    def extract_objects(self, path):
        extract_files2 = f"tshark -Y 'http.content_type==\"application/x-shockwave-flash\" || " \
                         "http.content_type==\"application/java-archive\" || " \
                         f"http.content_type==\"application/x-msdownload\"' -r {pcap_path} --export-objects \"http," \
                         f"{path}\" "
        os.system(extract_files2)


def create_secure_dir():
    dir_path = input("Enter absolute path of new directory for file storage: ")
    if not os.path.isdir(dir_path):
        os.mkdir(dir_path)
        print("[+] Directory created.")
    else:
        print("[-] ERROR: Directory already exists.")
    return dir_path


def md5(filename):
    """ Create md5 hash of file to use for VT or WF upload
    :param filename: The file of which a hash value will be generated for. 'filename' will most likely be the iterator
                     in a for loop
    :return: Hash value
    """
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    hash_list.append(hash_md5.hexdigest())
    return hash_md5.hexdigest()


if __name__ == '__main__':
    pcap_path = input("Enter the path of the .pcap to analyze: ")
    file_list = []
    hash_list = []
    pcap = Packet(pcap_path)
    new_dir = create_secure_dir()
    pcap.extract_objects(new_dir)
    files = glob.iglob(str(new_dir) + "/*")  # output of 'create_secure_dir' goes here when complete
    for file in files:
        file_list.append(file)
    for k in file_list:
        print(f"{k}: " + md5(k))