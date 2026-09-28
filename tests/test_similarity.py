from src.similarity import calculate_similarity


text1 = "SSH service is accessible on port 22"
text2 = "An SSH service is exposed on port 22"


similarity = calculate_similarity(text1, text2)


print("Text 1:", text1)
print("Text 2:", text2)
print("Similarity:", similarity)