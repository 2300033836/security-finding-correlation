
from sentence_transformers import SentenceTransformer, util


MODEL_NAME = "all-MiniLM-L6-v2"

model = SentenceTransformer(MODEL_NAME)


def calculate_similarity(text1, text2):
    """Calculate semantic similarity between two texts."""

    text1 = str(text1 or "").strip()
    text2 = str(text2 or "").strip()

    if not text1 or not text2:
        return 0.0

    embeddings = model.encode(
        [text1, text2],
        convert_to_tensor=True,
        normalize_embeddings=True
    )

    similarity = util.cos_sim(
        embeddings[0],
        embeddings[1]
    ).item()

    return float(similarity)


def calculate_similarities(texts):
    """Generate reusable embeddings for multiple finding texts."""

    cleaned_texts = [
        str(text or "").strip()
        for text in texts
    ]

    if not cleaned_texts:
        return []

    return model.encode(
        cleaned_texts,
        convert_to_tensor=True,
        normalize_embeddings=True,
        show_progress_bar=False
    )


def compare_embeddings(embedding1, embedding2):
    """Compare two previously generated embeddings."""

    return float(
        util.cos_sim(embedding1, embedding2).item()
    )
